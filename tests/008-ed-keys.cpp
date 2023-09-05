#include <catch2/catch_test_macros.hpp>
#include <quic.hpp>
#include <quic/gnutls_crypto.hpp>
#include <thread>

#include "utils.hpp"

#include <oxenc/hex.h>

namespace oxen::quic::test
{
    using namespace std::literals;

    TEST_CASE("008 - Ed Keys: Types", "[001][keys][tls][types]")
    {
      auto valid_seed = oxenc::from_hex("468e7ed2cd914ca44568e7189245c7b8e5488404fc88a4019c73b51d9dbc48a5");
      auto valid_pubkey = oxenc::from_hex("626136fe40c8860ee5bdc57fd9f15a03ef6777bb9237c18fc4d7ef2aacfe4f88");

      auto valid_seed2 = oxenc::from_hex("fefbb50cdd4cde3be0ae75042c44ff42b026def4fd6be4fb1dc6e81ea0480c9b");
      auto valid_pubkey2 = oxenc::from_hex("d580d5c68937095ea997f6a88f07a86cdd26dfa0d7d268e80ea9bbb5f3ca0304");

      SECTION("Bad Input")
      {
        REQUIRE_THROWS(GNUTLSCreds::make_from_ed_keys("", ""));
        REQUIRE_THROWS(GNUTLSCreds::make_from_ed_keys("notavalidkey", valid_pubkey));
        REQUIRE_THROWS(GNUTLSCreds::make_from_ed_keys(valid_seed, "notavalidkey"));

        // Both of these should error in gnutls (which I then throw) according to gnutls docs, but do not.
        REQUIRE_THROWS(GNUTLSCreds::make_from_ed_keys(valid_seed, valid_pubkey2)); // mismatch
        REQUIRE_THROWS(GNUTLSCreds::make_from_ed_keys(valid_pubkey, valid_seed)); // wrong order
      };

      SECTION("Keys Load Correctly")
      {
        REQUIRE_NOTHROW(GNUTLSCreds::make_from_ed_keys(valid_seed, valid_pubkey));
      };
    };

}  // namespace oxen::quic::test
