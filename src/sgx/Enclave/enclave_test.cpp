#include <algorithm>

#include "bitcoin/uint256.h"
#include "blockfifo.h"
#include "crypto_box.h"
#include "lest/lest.hpp"
#include "securechannel.h"
#include "state.h"

#include "bitcoin/utilstrencodings.h"
#include "bitcoin_helpers.h"
#include "settle.h"
#include "bitcoin/streams.h"
#include "../common/utils.h"


using namespace std;

const lest::test specification[] = {
    {CASE("calc the number of leading zeroes in uint256"){uint256 a;
a.SetHex("0000000011111111111111111111111111111111111111111111111111111111");
EXPECT(8 == get_num_of_leading_zeroes(a));
a.SetHex("0111111111111111111111111111111111111111111111111111111111111111");
EXPECT(1 == get_num_of_leading_zeroes(a));
a.SetHex("1111111111111111111111111111111111111111111111111111111111111111");
EXPECT(0 == get_num_of_leading_zeroes(a));
}
}
, {CASE("generate new address"){const uint32_t cltvTimeout = 1547578486;
CBitcoinSecret secret;
secret.SetString("cURgah32X7tNqK9NCkpXVVd4bbocWm3UjgwyAGpdVfxicAZynLs5");
auto script =
    generate_simple_cltv_script(secret.GetKey().GetPubKey(), cltvTimeout);
auto addr = create_p2sh_address(script);
EXPECT(addr.ToString() == "2N7GnzMovd5tq1DpMQXDx6KfuGW2m6RbXpN");
}
}
, {CASE("generate new address from complex scripts"){
      const uint32_t cltvTimeout = 1000000;
CBitcoinSecret user_secret, exch_secret;
user_secret.SetString("cTvTf14w41TZMiKNyxiqCFLitgR7zZW1q8RHxMmMQXAcoQR4A966");
exch_secret.SetString("cQWk83QU1v5kEDLznW12TLH6nqemmJ3T6bhKwgwfTawTGKeyRtFc");

auto script = generate_deposit_script(
    user_secret.GetKey().GetPubKey(),
    exch_secret.GetKey().GetPubKey(),
    cltvTimeout);
auto addr = create_p2sh_address(script);
EXPECT(addr.ToString() == "2NGFQnjaHX38fmS1di3MH8bf9Hd6NZxZTzv");
}
}
,

    {CASE("depositparam class"){const uint32_t cltvTimeout = 1000000;
CBitcoinSecret user_secret(seckey_from_str("alice")),
    exch_secret(seckey_from_str("exch"));
DepositParams params(
    "alice",
    user_secret.GetKey().GetPubKey(),
    exch_secret.GetKey().GetPubKey(),
    cltvTimeout);
auto redeemScript = params.deposit_redeemScript();
EXPECT(params.address().ToString() == "2NAqCFC8FazvtUzGv23reB9kQyR9JBW48PB");

auto scriptPubkey = params.scriptPubkey();
EXPECT(
    HexStr(scriptPubkey.begin(), scriptPubkey.end()) ==
    "a914c0e6d37a01c9999d88b4dc252a39e571bea1603a87");
EXPECT(
    HexStr(redeemScript.begin(), redeemScript.end()) ==
    "6376a914966f83de4b1901794baec6a42322f8080db166cc88ac670340420fb17576a91466"
    "24a4de9b4973cba3b991bc26cd1c8f171a4e3d88ac68");
}
}
,

    {CASE("seckey"){CBitcoinSecret secret(seckey_from_str("exch"));
EXPECT(
    secret.ToString() ==
    "cUCtr5hzrXKXsrpbZBM644kK1G7E3CzXdNPvDWYxt4FF7LxqZ9vz");

secret.SetKey(seckey_from_str("alice"));
EXPECT(
    secret.ToString() ==
    "cTvTf14w41TZMiKNyxiqCFLitgR7zZW1q8RHxMmMQXAcoQR4A966");
}
}
,
}
;

int test_securechannel()
{
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
  } catch (const exception &e) {
    LL_CRITICAL("%s", e.what());
  }
  return 0;
}

using namespace exch::enclave;

#include "settle.h"

extern bool test_simple_cltv_redeem();
int enclaveTest()
{
  //  test_simple_cltv_redeem();
  //  test_settlement();
  //  test_settle_all();
  // SelectParams(CBaseChainParams::REGTEST);
  return 0;
}

void sign_n_times(int n)
{
  ECC_Start();
  auto _ = std::unique_ptr<ECCVerifyHandle>(new ECCVerifyHandle());
  auto _mem = std::unique_ptr<char[]>(new char[95 * 1024 * 1024]);
  auto key = seckey_from_str("test");
  uint256 hash;
  vector<uint8_t> vchSig;

  for (int i = 0; i < n; i++) {
    key.Sign(hash, vchSig);
  }
  ECC_Stop();
}

int generate_settlement_tx(
        int num_input_bitcoin, int num_output_bitcoin,
        unsigned char* deposit_tx_hex_bitcoin,
        size_t* size_bitcoin,
        int num_input_litecoin, int num_output_litecoin,
        unsigned char* deposit_tx_hex_litecoin,
        size_t* size_litecoin) {
    LL_NOTICE("start generating settlement transaction...");
   
    int ret = 0;

    SelectParams(CBaseChainParams::TESTNET);
    ECC_Start();

    try {
        std::pair<CTransaction, CTransaction> tx1_pair = _do_test_settlement_all(
                num_input_bitcoin, num_output_bitcoin, deposit_tx_hex_bitcoin, size_bitcoin);

        std::pair<CTransaction, CTransaction> tx2_pair = _do_test_settlement_all(
                num_input_litecoin, num_output_litecoin, deposit_tx_hex_litecoin, size_litecoin);
      
        unsigned char *tx_tmp = new unsigned char[33];
        hex2bin(tx_tmp, HexStr(tx1_pair.first.GetHash()).c_str());
        byte_swap(tx_tmp, 32);
        string tx_1_id = bin2hex(tx_tmp, 32);
        LL_NOTICE("settment tx1 id: %s", tx_1_id.c_str());        
        
        hex2bin(tx_tmp, HexStr(tx1_pair.second.GetHash()).c_str());
        byte_swap(tx_tmp, 32);
        string tx_1_cancel_id = bin2hex(tx_tmp, 32);
        LL_NOTICE("cancellation tx1 id: %s", tx_1_cancel_id.c_str());
        delete[] tx_tmp;
  
        bytes tx1, tx2, tx1_cancel, tx2_cancel;
        {
            CDataStream ss(SER_NETWORK, PROTOCOL_VERSION);
            ss << tx1_pair.first;
            tx1 = ToByteVector(ss);
        }
        {
            CDataStream ss(SER_NETWORK, PROTOCOL_VERSION);
            ss << tx2_pair.first;
            tx2 = ToByteVector(ss);
        }
        {
            CDataStream ss(SER_NETWORK, PROTOCOL_VERSION);
            ss << tx1_pair.second;
            tx1_cancel = ToByteVector(ss);
        }
        {
            CDataStream ss(SER_NETWORK, PROTOCOL_VERSION);
            ss << tx2_pair.second;
            tx2_cancel = ToByteVector(ss);
        }
        LL_NOTICE("generation finished...");
        fairness::SettlementPkg msg(
                tx_1_id, tx_1_cancel_id, tx1, tx2, tx1_cancel, tx2_cancel);

        State &s = State::getInstance();
        fairness::Leader *prot = s.initFairnessProtocol(move(msg));

    } catch (const std::exception &e) {
      LL_CRITICAL("error happened: %s", e.what());
      ret = -1;
    } catch (...) {
      LL_CRITICAL("unknown error happened");
      ret = -1;
    }

    ECC_Stop();
    return ret;
}


int simulate_leader()
{
  LL_NOTICE("launching leader...");

  try {
    State &s = State::getInstance();

    LL_NOTICE("starting settlement...");
    (s.getProtocolLeader())->disseminate();

    return 0;
  }
  CATCH_STD_AND_ALL
}
