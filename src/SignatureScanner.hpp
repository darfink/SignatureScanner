#pragma once

#include <cstdint>
#include <stdexcept>
#include <string>
#include <vector>
#include <limits>

namespace {
typedef unsigned char byte;
typedef unsigned long ulong;
}

/* Signature scanner
 *
 * The signature scanner implements a cross-platform way of searching for
 * binary patterns within the memory of the current process. This is performed
 * by starting from a base address and continuing comparing bytes to the
 * signature, ignoring specific indexes specified by the accompanied mask.
 *
 * ###Example
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
     * @allModules Specifies whether all modules within the current process
     *             should be added or not.
     */
    explicit SignatureScanner(bool allModules = false);

    /* Signature scanner destructor
     *
     * The destructor deallocates any occupied memory and closes all module
     * handles (if they are to be retained, the reference count must increment)
     */
    virtual ~SignatureScanner();

    /* Add a library module
     *
     * Resolves an address into the module that contains it. The entire module
     * will be indexed and added to the region list. Any signature searches
     * can be specifically for this module or combined with all other regions
     * added.
     *
     * @containedAddress An address that resides within the module that is to
     *                   be added to the module collection.
     */
    void AddModule(void* containedAddress);

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
     * @signature The description of the signature pattern in hex values.
     *            Values that are to be ignored by the mask can be any value.
     *
     * @mask The mask consists of a character array that must have an equal
     *       compared to the the signature. Each index corresponds to the
     *       respective index of the signature. A question mark character
     *       indicates that the byte should be ignored. Any other mask value
     *       includes the byte in the pattern search. The mask must be
     *       null-terminated.
     *
     * @offset The offset is added (or subtracted) to the final address
     *
     * @length Babasdasd
     *
     * @return The memory address of the first match of the signature,
     *         otherwise zero is returned (i.e null).
     */
    uintptr_t FindSignature(
    	const std::vector<byte>& signature,
    	const char* mask,
    	size_t offset = 0,
        size_t length = std::numeric_limits<size_t>::max()) const;

    /* Search for a module symbol
     *
     */
    void* FindSymbol(const std::string& symbol);

private:
#ifndef _WIN32
    /* Get a modules size in memory
     *
     * @baseAddress Wtf
     *
     * @return Douchebag
     */
    size_t GetModuleSize(uintptr_t baseAddress);
#endif

    /*
     *
     */
    uintptr_t FindSignature(
            size_t baseAddress,
            size_t length,
            const std::vector<byte>& signature,
            const char* mask);

    /* Memory region
     *
     * A structure that describes a searchable region in memory with a base
     * address, length and a module handle.
     */
    struct Region {
        uintptr_t baseAddress;
        size_t baseLength;
        void* handle;
    };

    // Private members
    std::vector<Region> mRegions;
};
