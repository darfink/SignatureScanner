#include <cassert>
#include <cstring>
#include <algorithm>
#include <vector>
#ifdef _WIN32
# include <windows.h>
#else /* POSIX */
# include <cstdio>
# include <fstream>
# include <sys/mman.h>
# include <dlfcn.h>
#endif

#include "SignatureScanner.hpp"

namespace {
template<typename T, size_t Size>
constexpr size_t GetArraySize(T(&)[Size]) { return Size; }
}
#include <unistd.h>
SignatureScanner::SignatureScanner(void* containedAddress) :
    mBaseAddress(0),
    mModuleSize(0)
{
  assert(containedAddress != nullptr);

#ifdef _WIN32
  HMODULE module;
  if(!GetModuleHandleEx(
      GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS,
      containedAddress)) {
    throw Exception("couldn't retrieve memory module handle");
  }

  mModuleHandle.reset(module, +[](void* handle) {
    if(handle != nullptr) { FreeLibrary(handle); }
  });

  MODULEINFO* moduleInfo;
  if(!GetModuleInformation(
      GetCurrentProcess(),
      module,
      &moduleInfo,
      sizeof(MODULEINFO))) {
    throw Exception("couldn't retrieve module information");
  }

  mBaseAddress  = reinterpret_cast<uintptr_t>(moduleInfo.lpBaseOfDll);
  mModuleSize   = moduleInfo.SizeOfImage;
#else /* POSIX */
  Dl_info info;
  if(!dladdr(containedAddress, &info)) {
    throw Exception("couldn't retrieve memory information from address");
  }

  mModuleHandle.reset(dlopen(info.dli_fname, RTLD_NOW), +[](void* handle) {
    if(handle != nullptr) { dlclose(handle); }
  });

  if(!mModuleHandle) {
    throw Exception("couldn't open module handle");
  }

  mBaseAddress = reinterpret_cast<uintptr_t>(info.dli_fbase);
  mModuleSize  = this->CalculateModuleSize(info.dli_fbase);
#endif
}

uintptr_t SignatureScanner::FindSignature(
    const std::vector<byte>& signature,
    const char* mask,
    size_t offset /*= 0*/,
    size_t length /*= npos*/) const {
  assert(mask != nullptr);
  assert(signature.size() == strlen(mask));

  uintptr_t start = mBaseAddress + offset;
  uintptr_t end = mBaseAddress + std::min(mModuleSize, length);

  assert(start < end);

  MemoryInformation memoryInfo;
  size_t x = 0;

  while(start < end) {
    size_t region = 0;
    this->GetMemoryInfo(reinterpret_cast<void*>(start), &memoryInfo);

    // Calculate the bounds for the current memory region
    region = reinterpret_cast<uintptr_t>(memoryInfo.baseAddress) +
      memoryInfo.regionSize;

    if(!this->IsMemoryAccessible(memoryInfo)) {
      start = region;
      x = 0;

      continue;
    }

    for(bool quit = false; start < region && !quit; start++) {
      for(; x < signature.size(); x++) {
        // Ensure that we aren't intruding in a new memory region
        if((start + x) >= region) {
          // We must decrement 'x', otherwise it might equal 'signature.size()'
          // and we 'think' we have a match
          quit = true;
          x--;

          break;
        }

        // Exit the loop if the signature did not match with the source
        if(mask[x] != '?' && signature[x] != reinterpret_cast<byte*>(start)[x]) {
          break;
        }
      }

      // If the increment count equals the signature length,
      // we know we have a match!
      if(x == signature.size()) {
        return start;
      } else {
        x = 0;
      }
    }
  }

  return 0;
}

void* SignatureScanner::FindSymbol(const std::string& symbol) const {
#ifdef _WIN32
  return GetProcAddress(mModuleHandle.get(), symbol.c_str());
#else /* POSIX */
  return dlsym(mModuleHandle.get(), symbol.c_str());
#endif
}

void SignatureScanner::GetMemoryInfo(
    const void* address,
    MemoryInformation* memoryInfo) const {
  assert(memoryInfo != nullptr);
  assert(address != nullptr);

#ifdef _WIN32
  MEMORY_BASIC_INFORMATION memoryBasicInformation;
  if(!VirtualQuery(
      address,
      &memoryBasicInformation,
      sizeof(MEMORY_BASIC_INFORMATION))) {
    throw Exception("couldn't retrieve basic memory information");
  }

  memoryInfo->baseAddress = reinterpret_cast<uintptr_t>(memoryBasicInformation.BaseAddress);
  memoryInfo->regionSize = memoryBasicInformation.RegionSize;
  memoryInfo->protection = memoryBasicInformation.Protect;
  memoryInfo->state = memoryBasicInformation.State;
#else /* POSIX */
  const uintptr_t targetAddress = reinterpret_cast<uintptr_t>(address);

  std::ifstream fstream("/proc/self/maps");
  std::string input;

  if(!fstream.good()) {
    throw Exception("couldn't open memory mapping information file");
  }

  char protection[4];
  uintptr_t lower, upper;
  bool found = false;

  while(!found && std::getline(fstream, input)) {
    if(sscanf(input.c_str(), "%lx-%lx %s", &lower, &upper, protection) != 3) {
      continue;
    }

    // Check if the address is located within the page
    if(targetAddress >= lower && targetAddress < upper) {
      // We have a match
      found = true;

      memoryInfo->baseAddress = reinterpret_cast<void*>(lower);
      memoryInfo->regionSize = upper - lower;
      memoryInfo->protection = 0;
      memoryInfo->state = 0;

      for(uint i = 0; i < GetArraySize(protection); i++) {
        switch(protection[i]) {
        default: assert(false);
        case 'r': memoryInfo->protection |= PROT_READ; break;
        case 'w': memoryInfo->protection |= PROT_WRITE; break;
        case 'x': memoryInfo->protection |= PROT_EXEC; break;
        case 'p': memoryInfo->state |= MAP_PRIVATE; break;
        case 's': memoryInfo->state |= MAP_SHARED; break;
        case '-': break;
        }
      }
    }
  }

  if(!found) {
    throw Exception("couldn't find memory information");
  }
#endif
}

#ifndef _WIN32
size_t SignatureScanner::CalculateModuleSize(const void* baseAddress) const {
  assert(baseAddress != nullptr);

  std::ifstream fstream("/proc/self/maps");
  std::string input;

  if(!fstream.good()) {
    throw Exception("couldn't open memory mapping information file");
  }

  bool found = false;
  uintptr_t address = reinterpret_cast<uintptr_t>(baseAddress);
  uintptr_t lower, upper, offset;
  char permissions[4];
  byte major, minor;
  uint inode;

  uintptr_t moduleBase, moduleEnd;
  uint moduleNode;

  while(std::getline(fstream, input)) {
    if(sscanf(input.c_str(), "%lx-%lx %s %lx %hhu:%hhu %du",
        &lower, &upper, permissions, &offset, &major, &minor, &inode) != 7) {
      continue;
    }

    if(address == lower && !found) {
      moduleBase = lower;
      moduleNode = inode;
      moduleEnd  = upper;

      found = true;
      continue;
    } else if(found) {
      if(inode != moduleNode) {
        break;
      }

      // Update the upper bound
      moduleEnd = upper;
    }
  }

  if(!found) {
    throw Exception("couldn't find memory module");
  }

  // Calculate the final module size
  return (moduleEnd - moduleBase);
}
#endif

bool SignatureScanner::IsMemoryAccessible(
    const MemoryInformation& memoryInfo) const {
#ifdef _WIN32
  const ulong Readable =
    PAGE_EXECUTE_READ      |
    PAGE_EXECUTE_READWRITE |
    PAGE_WRITECOPY         |
    PAGE_EXECUTE_WRITECOPY |
    PAGE_READONLY          |
    PAGE_READWRITE;

  if(!(memoryInfo.protection & Readable)) {
    return false;
  }

  // Uncommited memory isn't readable as well
  if(!(memoryInfo.state & MEM_COMMIT)) {
    return false;
  }

  // Guarded pages cause an access violation when accessed
  return !(memoryInfo.protection & PAGE_GUARD);
#else /* POSIX */
  return (memoryInfo.protection & PROT_READ);
#endif
}

/* vim: set ts=2 sw=2 expandtab: */
