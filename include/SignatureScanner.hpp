#pragma once

#include <cstdint>
#include <stdexcept>
#include <vector>
#include <memory>

namespace {
typedef unsigned char byte;
typedef unsigned int  uint;
typedef unsigned long ulong;
}

/* Signature scanner
 *
 * The signature scanner implements a cross-platform way of searching for
 * binary patterns within a module in the current process. This is performed
 * by starting from a base address and continuing comparing bytes to a
 * signature, ignoring specific indexes specified by the accompanied mask.
 *
 */
class SignatureScanner {
public:
    /* Signature scanner exception */
    class Exception : public std::runtime_error {
    public:
        explicit Exception(std::string error) : runtime_error(error.c_str()) {}
    };

    /* Construct a signature scanner
     *
     * Creates a signature scanner from an address located within a module.
     * The address is resolved into the module that contains it. If the address
     * cannot be resolved, an <Exception> will be thrown. All memory regions
     * that are readable within the module is indexed.
     *
     * @containedAddress An address that resides within a module
     */
    explicit SignatureScanner(void* containedAddress);

    /* Search for a signature
     *
     * Tries to find a signature within the constructed memory region. If
     * an OS call fails during the scan an <Exception> will be thrown. Any
     * memory page and/or region that is read-protected will skipped in the
     * search. This includes regions that are page guarded on Windows.
     *
     * The search is done by using simple pointer arithmetics. The comparison
     * is done by using direct memory access of the processed region and the
     * supplied byte signature.
     *
     * NOTE: The method does not throw an <Exception> when no result is found.
     *
     * @signature The description of the signature pattern in hex values.
     *            Values that are to be ignored by the mask can be any value.
     *
     * @mask The mask consists of a character array that must have an equal
     *       length compared to the the signature. Each index corresponds to the
     *       respective index of the signature. A question mark character
     *       indicates that the byte should be ignored. Any other mask value
     *       includes the byte in the pattern search. The mask must be
     *       null-terminated.
     *
     * @offset The start offset for the search. The value is relative to the
     *         modules base address. An offset of zero will search from start.
     *
     * @length The maximum distance the search will be performed (counted in
     *         bytes). The length will be capped to the module size.
     *
     * @return The memory address of the first match of the signature,
     *         otherwise zero is returned (i.e null).
     */
    uintptr_t FindSignature(
    	const std::vector<byte>& signature,
    	const char* mask,
    	size_t offset = 0,
      size_t length = npos) const;

    /* Search for a module symbol
     *
     * Uses the native OS method (e.g 'dlsym', 'GetProcAddress') for retrieving
     * a symbol within the module.  * This method is merely exposed as a
     * convenience for the user.
     *
     * @symbol The unique symbol to resolve within the module
     *
     * @return The symbol address, otherwise zero is returned (i.e null).
     */
    void* FindSymbol(const std::string& symbol) const;

    /* Get the base address of the module
     *
     * @return The base address of the module.
     */
    void* GetBaseAddress() const;

    /* Get the size of the module
     *
     * @return The size of the module in bytes.
     */
    size_t GetModuleSize() const;

public:
    /* Maximum value for size_t
     *
     * This exists to mimic the functionality of 'std::string::substr' in the
     * standard string class, but for memory regions instead.
     */
    static const size_t npos = -1;

private:
    /* Describes a region of memory
     *
     * The base address is not necessarily a base address of a module,
     * but can also be the base address of a memory map. The region size is
     * always equal to one page one Linux, whilst it can be the size of several
     * continuous memory regions (with the same permissions) on Windows. The
     * protection variable is a bitset of several flags, they are OS specific.
     *
     * State contains the mapping information on Linux (private or shared),
     * and the allocation type on Windows.
     */
    struct MemoryInformation {
        void* baseAddress;
        size_t regionSize;
        ulong protection;
        uint state;
    };

    /* Get an address's memory region information
     *
     * The memory information is retrieved by using OS specific functionality.
     * If the information cannot be retrieved an <Exception> is thrown.
     *
     * @address An address within the region of interest.
     *
     * @memoryInfo A pointer to a mutable memory information object.
     */
    void GetMemoryInfo(
        const void* address,
        MemoryInformation* memoryInfo) const;

#ifndef _WIN32
    /* Calculate a mapped module's size
     *
     * Parses the memory mappings for the module to retrieve the start and end
     * address of a module in memory. The size is caluted by subtracting the
     * start address from the end address. If the necessary information cannot
     * be retrieved an <Exception> is thrown. This method is Linux specific.
     *
     * @baseAddress The base address of the target module.
     *
     * @return The size of the module in bytes.
     */
    size_t CalculateModuleSize(const void* baseAddress) const;
#endif

    /* Check if a memory region is accessible
     *
     * A simple check to see if the memory is readable. On Linux the absence of
     * PROT_READ is evaluated, whilst a combination of several flags are checked
     * on Windows.
     *
     * @memoryInfo A memory information object describing the protection flags
     *             of the region of interest.
     *
     * @return True if the memory is accessible, otherwise false.
     */
    bool IsMemoryAccessible(const MemoryInformation& memoryInfo) const;

    // Private members
    std::shared_ptr<void> mModuleHandle;
    uintptr_t mBaseAddress;
    size_t mModuleSize;
};

inline void* SignatureScanner::GetBaseAddress() const {
  return reinterpret_cast<void*>(mBaseAddress);
}

inline size_t SignatureScanner::GetModuleSize() const {
  return mModuleSize;
}

/* vim: set ts=2 sw=2 expandtab: */
