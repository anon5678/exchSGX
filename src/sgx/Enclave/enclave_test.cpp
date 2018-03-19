#include <algorithm>

#include "lest.hpp"

#include "bitcoin/uint256.h"
#include "blockfifo.hpp"

#include "sgx_trts.h"
#include "crypto_box.h"
#include "securechannel.h"

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

  string msg {1,2,3,4,5};

  Peer peerA("localhost", 1234, pkA, skA);
  Peer peerB("localhost", 4321, pkB, skB);

  try {
    for (auto i = 0; i < 10; i++) {
      Box boxAtoB = peerA.createBoxToPeer(peerB, msg);
      string msgB = peerB.openBoxFromPeer(boxAtoB, peerA);
      hexdump("B received:", msgB.data(), msgB.size());
    }
  }
  catch (const exception& e) {
    LL_CRITICAL("%s", e.what());
  }
  return 0;
}

#include "state.h"
#include "fairness.h"
#include <algorithm>

using namespace exch::enclave;

int enclaveTest() {
  return 0;
}

int simulate_leader(uint16_t peerport, uint16_t leaderport) {
  LL_NOTICE("launching leader...");

  State& s = State::getInstance();
  Peer peer("localhost", peerport, string(crypto_box_PUBLICKEYBYTES, 0x90));
  s.addPeer(peer);

  LL_NOTICE("peer added. Now %d peers.", s.getPeerList().size());

  string leaderSk;
  string leaderPk = nacl_crypto_box_keypair(&leaderSk);

  Peer leader_info("localhost", leaderport, leaderPk, leaderSk);

  fairness::Message msg;
  vector<Peer> peerList;
  copy(s.getPeerList().begin(), s.getPeerList().end(), back_inserter(peerList));
  fairness::Leader leader(leader_info, peerList, msg);

  leader.disseminate();
  return 0;
}

