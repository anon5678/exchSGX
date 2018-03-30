#include <algorithm>

#include "lest.hpp"
#include "bitcoin/uint256.h"
#include "blockfifo.hpp"
#include "crypto_box.h"
#include "securechannel.h"
#include "state.h"

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

int test_securechannel() {
  using namespace exch::enclave::securechannel;

  string skA;
  string pkA = nacl_crypto_box_keypair(&skA);

  string skB;
  string pkB = nacl_crypto_box_keypair(&skB);

  string msg{1, 2, 3, 4, 5};

  Peer peerA("localhost", 1234, pkA, skA);
  Peer peerB("localhost", 4321, pkB, skB);

  try {
    for (auto i = 0; i < 10; i++) {
      Box boxAtoB = peerA.createBoxToPeer(peerB, msg);
      string msgB = peerB.openBoxFromPeer(boxAtoB, peerA);
      hexdump("B received:", msgB.data(), msgB.size());
    }
  }
  catch (const exception &e) {
    LL_CRITICAL("%s", e.what());
  }
  return 0;
}

using namespace exch::enclave;

int enclaveTest() {
  return 0;
}

int simulate_leader() {
  LL_NOTICE("launching leader...");

  try {
    State &s = State::getInstance();

    // TODO: put real data in here
    string tx_1_id = "288bcaaa05389922d5da1ee0e6d2d08e72770754e0c830adba50e0daa95efd48";
    string tx_1_cancel_id = "288bcaaa05389922d5da1ee0e6d2d08e72770754e0c830adba50e0daa95efd40";
    bytes tx1{1, 2, 3, 4};
    bytes tx2{1, 2, 3, 4};
    bytes tx1_cancel{1, 2, 3, 4};
    bytes tx2_cancel{1, 2, 3, 4};

    fairness::SettlementPkg msg(
        tx_1_id, tx_1_cancel_id,
        tx1, tx2,
        tx1_cancel, tx2_cancel);

    fairness::Leader *prot = s.initFairnessProtocol(move(msg));
    LL_NOTICE("starting settlement...");
    prot->disseminate();

    return 0;
  }
  CATCH_STD_AND_ALL
}

