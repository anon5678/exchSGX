//
// Created by fanz on 8/27/17.
//
#include <algorithm>

#include "lest.hpp"

#include "bitcoin/uint256.h"
#include "blockfifo.hpp"

#include "nacl/tweetnacl.h"

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

  unsigned char pk[crypto_box_PUBLICKEYBYTES];
  unsigned char sk[crypto_box_SECRETKEYBYTES];
  crypto_box_keypair(pk, sk);

  unsigned char n[crypto_box_NONCEBYTES];
  sgx_read_rand(n, sizeof n);

  bytes msg {1,2,3,4};

  // pad with zeroes
  msg.insert(msg.begin(), crypto_box_ZEROBYTES, 0);

  bytes cipher(msg.size());
  std::fill(cipher.begin(), cipher.end(), 0);

  int ret = crypto_box(cipher.data(), msg.data(), msg.size(), n, pk, sk);
  if (ret) {
    LL_CRITICAL("crypto box returned %d", ret);
  }

  hexdump("cipher", cipher.data(), cipher.size());

  bytes new_msg(cipher.size());
  ret = crypto_box_open(new_msg.data(), cipher.data(), cipher.size(), n, pk, sk);
  if (ret) {
    LL_CRITICAL("crypto box returned %d", ret);
  }

  hexdump("msg", new_msg.data(), new_msg.size());

  return 0;
}
