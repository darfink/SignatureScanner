#include <cassert>
#include <cstring>
#include <vector>
#ifdef _WIN32
# include <windows.h>
#else /* POSIX */
# define _POSIX_C_SOURCE 200809L
# include <cstdio>
# include <fstream>
# include <dlfcn.h>
# include <link.h>
# include <sys/stat.h>
#endif

#include "SignatureScanner.hpp"

#ifdef _WIN32
namespace {
// The required flags for a memory region to be accessable
const ulong ReadableRegion =
  PAGE_EXECUTE_READ      |
  PAGE_EXECUTE_READWRITE |
  PAGE_WRITECOPY         |
  PAGE_EXECUTE_WRITECOPY |
  PAGE_READONLY          |
  PAGE_READWRITE;
}
#endif

SignatureScanner::SignatureScanner(bool allModules = /*false*/) {
    if(!allModules) {
        return;
    }
}

SignatureScanner::~SignatureScanner() {
    for(Region& region : mRegions) {
        if(!region.handle) {
            continue;
        }

#ifdef _WIN32
        FreeLibrary(region.handle);
#else /* POSIX */
        dlclose(region.handle);
#endif
    }
}

void SignatureScanner::AddModule(void* containedAddress) {
    assert(containedAddress);

    Region region;

#ifdef _WIN32
    HMODULE module;
    if(!GetModuleHandleEx(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS, containedAddress)) {
        throw Exception("couldn't retrieve memory module handle");
    }

    MODULEINFO* moduleInfo;
    if(!GetModuleInformation(GetCurrentProcess(), module, &moduleInfo, sizeof(MODULEINFO))) {
        FreeLibrary(module);

        throw Exception("couldn't retrieve module information");
    }

    region.baseAddress = reinterpret_cast<uintptr_t>(moduleInfo.lpBaseOfDll);
    region.baseLength = moduleInfo.SizeOfImage;
    region.handle = module;
#else /* POSIX */
    Dl_info info;
    if(!dladdr(containedAddress, &info)) {
        throw Exception("couldn't retrieve memory information from address");
    }

    region.baseAddress = reinterpret_cast<uintptr_t>(info.dli_fbase);
    region.baseLength = this->GetModuleSize(region.baseAddress);
    region.handle = dlopen(info.dli_fname, RTLD_NOW);

    if(!region.handle) {
        throw Exception("couldn't open module handle");
    }
#endif
}

uintptr_t SignatureScanner::FindSignature(
    const std::vector<byte>& signature,
    const char* mask,
    int offset /*= 0*/) const {
  assert(signature.size() == strlen(mask));

  uintptr_t start = mBaseAddress;
  uintptr_t end = mBaseAddress + mBaseLength;

  size_t x = 0;

#ifdef _WIN32
  MEMORY_BASIC_INFORMATION memInfo;
#else /* POSIX */
  std::ifstream procMaps("/proc/self/maps");
  std::string input;

  if(!procMaps.good()) {
    throw Exception("couldn't retrieve memory mapping information");
  }
#endif
  while(start < end) {
    size_t region = 0;
#ifdef _WIN32
    // We don't want to access protected memory (will cause an access violation)
    if(!VirtualQuery(
        reinterpret_cast<void*>(start),
        &memInfo,
        sizeof(MEMORY_BASIC_INFORMATION))) {
      throw Exception("couldn't query memory information");
    }

    // Calculate the bounds for the current memory region
    region = reinterpret_cast<uintptr_t>(memInfo.BaseAddress) +
      memInfo.RegionSize;

    if(!(memInfo.Protect & ReadableRegion) ||
       !(memInfo.State & MEM_COMMIT) ||
       (memInfo.Protect & PAGE_GUARD)) {
      start = region;
      x = 0;

      continue;
    }
#else /* POSIX */
    if(procMaps.eof()) {
      return 0;
    }

    while(std::getline(procMaps, input)) {
      ulong lower, upper;
      char read;

      if(std::sscanf(input.c_str(), "%lx-%lx %c", &lower, &upper, &read) != 3) {
        throw Exception("couldn't parse memory information");
      }

      // We do not need to check the lower limit since the memory maps
      // are ordered lowest-to-highest address in the procedure mappings
      if(start >= lower) {
        if(read != 'r') {
          continue;
        }

        region = upper;
        break;
      }
    }
#endif
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
        return start + offset;
      } else {
        x = 0;
      }
    }
  }

  return 0;
}

void* SignatureScanner::FindSymbol(const std::string& symbol) {
#ifdef _WIN32
#else /* POSIX */
#endif
}
