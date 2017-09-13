//
// Created by fanz on 8/27/17.
//

#include "lest.hpp"

#include "bitcoin/uint256.h"
#include "blockfifo.h"

#include "log.h"

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
  lest::run(specification);
}
