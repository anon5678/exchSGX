#include <algorithm>

#include "lest/lest.hpp"
#include "bitcoin/uint256.h"
#include "blockfifo.hpp"
#include "crypto_box.h"
#include "securechannel.h"
#include "state.h"

#include "bitcoin_helpers.h"
#include "bitcoin/utilstrencodings.h"
#include "settle.h"

using namespace std;

const lest::test specification[] =
    {
        {CASE("calc the number of leading zeroes in uint256") {
      uint256 a;
      a.SetHex("0000000011111111111111111111111111111111111111111111111111111111");
          EXPECT(8 == nLeadingZero(a));
      a.SetHex("0111111111111111111111111111111111111111111111111111111111111111");
          EXPECT(1 == nLeadingZero(a));
      a.SetHex("1111111111111111111111111111111111111111111111111111111111111111");
          EXPECT(0 == nLeadingZero(a));
    }},
        {CASE("generate new address") {
          const uint32_t cltvTimeout = 1547578486;
          CBitcoinSecret secret;
          secret.SetString("cURgah32X7tNqK9NCkpXVVd4bbocWm3UjgwyAGpdVfxicAZynLs5");
          auto script = generate_simple_cltv_script(secret.GetKey().GetPubKey(), cltvTimeout);
          auto addr = create_p2sh_address(script);
              EXPECT(addr.ToString() == "2N7GnzMovd5tq1DpMQXDx6KfuGW2m6RbXpN");
        }},
        {CASE("generate new address from complex scripts") {
          const uint32_t cltvTimeout = 1000000;
          CBitcoinSecret user_secret, exch_secret;
          user_secret.SetString("cTvTf14w41TZMiKNyxiqCFLitgR7zZW1q8RHxMmMQXAcoQR4A966");
          exch_secret.SetString("cQWk83QU1v5kEDLznW12TLH6nqemmJ3T6bhKwgwfTawTGKeyRtFc");

          auto script =
              generate_deposit_script(user_secret.GetKey().GetPubKey(), exch_secret.GetKey().GetPubKey(), cltvTimeout);
          auto addr = create_p2sh_address(script);
              EXPECT(addr.ToString() == "2NGFQnjaHX38fmS1di3MH8bf9Hd6NZxZTzv");
        }},

        {CASE("depositparam class") {
          const uint32_t cltvTimeout = 1000000;
          CBitcoinSecret user_secret, exch_secret;
          user_secret.SetString("cTvTf14w41TZMiKNyxiqCFLitgR7zZW1q8RHxMmMQXAcoQR4A966");
          exch_secret.SetString("cUCtr5hzrXKXsrpbZBM644kK1G7E3CzXdNPvDWYxt4FF7LxqZ9vz");

          DepositParams params(user_secret.GetKey().GetPubKey(), exch_secret.GetKey().GetPubKey(), cltvTimeout);
          auto redeemScript = params.deposit_redeemScript();
          EXPECT(params.address().ToString() == "2N5hCfJu7Rhm7mcyHoWSj7AqXbcNRvbnayt");
        }},
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

extern void test_bitcoin_transaction();
int enclaveTest() {
  /// state_balance.cpp:504
  test_bitcoin_transaction();
  SelectParams(CBaseChainParams::REGTEST);
  ECC_Start();
  lest::run(specification);
  ECC_Stop();
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