#include <algorithm>

#include "lest.hpp"

#include "bitcoin/uint256.h"
#include "blockfifo.hpp"

#include "nacl/crypto_box.h"

#include "sgx_trts.h"

using namespace std;

const lest::test specification[] =
    {
        CASE("calc the number of leading zeroes in uint256") {
      uint256 a;
      a.SetHex("0000000011111111111111111111111111111111111111111111111111111111");
          EXPECT(8 == nLeadingZero(a));
      a.SetHex("0111111111111111111111111111111111111111111111111111111111111111");
          EXPECT(1 == nLeadingZero(a));
      a.SetHex("1111111111111111111111111111111111111111111111111111111111111111");
          EXPECT(0 == nLeadingZero(a));
    },
    };

int enclaveTest() {
//  return lest::run(specification);

  string pk, sk;
  pk = nacl::crypto_box_keypair(&sk);

  unsigned char n[crypto_box_NONCEBYTES];
  sgx_read_rand(n, sizeof n);
  string nonce((char*) n, sizeof n);

  string msg {1,2,3,4};
  string cipher;

  cipher = nacl::crypto_box(msg, nonce, pk, sk);

  hexdump("cipher", cipher.data(), cipher.size());

  string plain;
  plain = nacl::crypto_box_open(cipher, nonce, pk, sk);

  hexdump("msg", plain.data(), plain.size());

  return 0;
}
