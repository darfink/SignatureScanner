#include <vector>

#define CATCH_CONFIG_MAIN
#include "catch.hpp"
#include "library.hpp"

namespace {
typedef unsigned char byte;
}

TEST_CASE("scanner", "The signature scanner") {
  SignatureScanner scanner(reinterpret_cast<void*>(&Add));

  SECTION("basic", "It has valid values") {
    REQUIRE(scanner.GetBaseAddress() != nullptr);
    REQUIRE(scanner.GetModuleSize() > 0);
  }

  SECTION("local", "It finds the 'Add' function") {
    const size_t BytesToCompare = 10;

    std::vector<byte> signature(BytesToCompare);
    std::string mask(BytesToCompare, 'x');

    for(int i = 0; i < BytesToCompare; i++) {
      signature.push_back(reinterpret_cast<byte*>(&Add)[i]);
    }

    REQUIRE(scanner.FindSignature(signature, mask.c_str()) == reinterpret_cast<uintptr_t>(&Add));
    mask[6] = '?';
    REQUIRE(scanner.FindSignature(signature, mask.c_str()) == reinterpret_cast<uintptr_t>(&Add));
    REQUIRE(reinterpret_cast<decltype(&Foo)>(scanner.FindSignature(signature, mask.c_str()))(5, 6) == 11);
  }
}
