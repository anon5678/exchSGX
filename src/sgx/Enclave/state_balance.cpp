#include "state.h"
#include "pprint.h"
#include "log.h"
#include "bitcoin/crypto/sha256.h"
#include "bitcoin/hash.h"

#include "../common/merkle_data.h"
#include "../common/base64.hxx"
#include "../common/utils.h"
#include "../common/common.h"

#include <string>

using namespace std;
using namespace exch::enclave;

// s1+s2 are the 32+32 bytes input, dst is 32 bytes output
// dst = hash(hash(s1 || s2))
static void sha256double(
    const unsigned char *s1,
    const unsigned char *s2,
    unsigned char *dst) {
  CSHA256 h1, h2;
  unsigned char tmp[BITCOIN_HASH_LENGTH];

  h1.Write(s1, BITCOIN_HASH_LENGTH);
  h1.Write(s2, BITCOIN_HASH_LENGTH);
  h1.Finalize(tmp);

  h2.Write(tmp, sizeof tmp);
  h2.Finalize(dst);
}

static void hash160(const unsigned char *src, size_t len, unsigned char *dst) {
  CSHA256 h1;
  unsigned char tmp[CSHA256::OUTPUT_SIZE];
  h1.Write(src, len);
  h1.Finalize(tmp);

  CRIPEMD160 h2;
  h2.Write(tmp, sizeof tmp);
  h2.Finalize(dst);
}

static uint256 __merkle_proof_verify(const merkle_proof_t *proof) {
  bitcoin_hash_t curr;

  memcpy(curr, proof->tx, sizeof curr);

  int direction = proof->dirvec;

  for (unsigned int i = 0; direction > 1 && i < proof->merkle_branch_len; ++i, direction >>= 1) {
    if (proof->merkle_branch[i] == nullptr) {
      sha256double(curr, curr, curr);
      continue;
    }
    if (direction & 1)
      sha256double(curr, *proof->merkle_branch[i], curr);
    else
      sha256double(*proof->merkle_branch[i], curr, curr);
  }

  return uint256B(curr, sizeof curr);
}

int merkle_proof_verify(const merkle_proof_t *proof) {
  LL_NOTICE("root: %s", __merkle_proof_verify(proof).GetHex().c_str());
  return 0;
}

typedef unsigned long long cointype;

static void fill_timelock_payment_template(unsigned char *aa, const unsigned char *RTEpk,
                                           int timeout, const unsigned char *refund) {
  int j = 0;
  aa[j++] = 0x63; // op_if
  aa[j++] = 0xa8; // op_sha256 (rm)
  aa[j++] = 0x20; // 32 bytes digest size (rm)
  // FIXME: Not relevant. will be removed later.
  std::memcpy(
      aa + j,
      (ext::b64_decode("x3Xnt1ft5jDNCqERO9ECZhqziCnKUqZCKreChi8mhkY=")).data(),
      32);           // sha256 digest (rm)
  aa[j + 32] = 0x88; // op_equalverify (rm)
  j += 33;
  aa[j++] = 0x21; // 33 bytes pubkey size
  std::memcpy(aa + j, RTEpk, 33);
  aa[j + 33] = 0xAC; // op_checksig
  j += 34;
  aa[j++] = 0x67; // op_else
  aa[j++] = 0x3;  // timeout size
  aa[j++] = timeout >> 16;
  aa[j++] = timeout >> 8;
  aa[j++] = timeout;
  aa[j++] = 0xb1; // op_CLTV
  aa[j++] = 0x75; // op_drop
  aa[j++] = 0x21; // 33 bytes pubkey size
  std::memcpy(aa + j, refund, 33);
  aa[j + 33] = 0xAC; // op_checksig
  aa[j + 34] = 0x68; // op_endif
}

static cointype validateDeposit(const unsigned char *tx,
                                size_t tx_len,
                                const unsigned char *RTEpubkey,
                                unsigned long timeout,
                                const unsigned char *refund) {
  if (1 != tx[4])
    return 0;                                      // single input
  int j = 5 + 32 + 4 + 1 + tx[5 + 32 + 4] + 4 + 1; // skip to first output
  cointype r = tx[j++];
  for (int i = 8; i <= 56; i += 8)
    r += cointype(tx[j++]) << i;
  if (23 != tx[j++])
    return 0; // p2sh size
  if (0xA9 != tx[j++])
    return 0; // op_hash160
  if (0x14 != tx[j++])
    return 0; // 20 bytes
  if (0x87 != tx[j + 20])
    return 0; // op_equal

  const unsigned char *p2sh_hash = tx + j;

  unsigned char arr[114];
  fill_timelock_payment_template(arr, RTEpubkey, timeout, refund);
  unsigned char res[20];
  hash160(arr, 114, res);

  if (0 != memcmp(p2sh_hash, res, 20)) {
    LL_CRITICAL("script hash mismatch");
    LL_DEBUG("hash in the tx: %s", bin2hex(tx + j, 20).c_str());
    LL_DEBUG("calculated hash: %s", bin2hex(res, 20).c_str());
    return 0;
  }

  return r;
}

int ecall_bitcoin_deposit(const bitcoin_deposit_t *deposit) {
  if (!deposit)
    return -1;

  try {
    // 0. find the block
    uint256 _block_hash;
    _block_hash.SetHex(deposit->block);
    const CBlockHeader *h = state::blockFIFO.find_block(_block_hash);
    if (h) {
      // 1. verify the integrity of tx_raw
      vector<unsigned char> tx_raw = hex2bin(deposit->tx_raw);

      unsigned char tmp[CSHA256::OUTPUT_SIZE];

      // hash the tx
      {
        CSHA256 tx_hash;
        tx_hash.Write(tx_raw.data(), tx_raw.size());
        tx_hash.Finalize(tmp);

        tx_hash.Reset();
        tx_hash.Write(tmp, sizeof tmp);
        tx_hash.Finalize(tmp);
      }

      if (0 != memcmp(tmp, deposit->merkle_proof->tx, sizeof tmp)) {
        LL_CRITICAL("tx binary corrupted");
        LL_CRITICAL("calculated hash (little-endian): %s", bin2hex(tmp, BITCOIN_HASH_LENGTH).c_str());
        LL_CRITICAL("expected hash (little-endian): %s",
                    bin2hex(deposit->merkle_proof->tx, BITCOIN_HASH_LENGTH).c_str());
        return -1;
      }

      LL_LOG("find block %s", h->GetHash().GetHex().c_str());
      uint256 calc_root = __merkle_proof_verify(deposit->merkle_proof);
      if (calc_root == h->hashMerkleRoot) {
        LL_NOTICE("deposit %s accepted", bin2hex(deposit->merkle_proof->tx, 32).c_str());

        const cointype amount = validateDeposit(tx_raw.data(),
                                                tx_raw.size(),
                                                hex2bin(deposit->deposit_recipient_addr).data(),
                                                deposit->deposit_timeout, // 0x389900,
                                                hex2bin(deposit->deposit_refund_addr).data());
        LL_NOTICE("depositing amount: %d", amount);
        state::balanceBook.deposit(deposit->pubkey_pem, amount);
      } else {
        LL_CRITICAL("deposit NOT accepted");
        LL_CRITICAL("expected root: \n%s", h->hashMerkleRoot.GetHex().c_str());
        LL_CRITICAL("calculated root: \n%s", calc_root.GetHex().c_str());
      }
    } else {
      LL_CRITICAL("doesn't find the block");
      return -1;
    }
  }
  catch (const std::exception &e) {
    LL_CRITICAL("Exception: %s", e.what());
    return -1;
  }

  LL_NOTICE("done deposit");

  return 0;
}

#include "script/script.h"
#include "primitives/transaction.h"
#include "pubkey.h"
#include "key.h"
#include "utilstrencodings.h"
#include "streams.h"
#include "script/sign.h"
#include "amount.h"

bool IsValidRedeemScript(const CScript& redeemScript, const CScript& scriptPubKey) {
  std::vector<unsigned char> redeemScript_bytes = ToByteVector(redeemScript);
  unsigned char hash_redeemScript[20];
  hash160(redeemScript_bytes.data(), redeemScript_bytes.size(), hash_redeemScript);
  std::vector<unsigned char> hash_redeemScript_bytes(hash_redeemScript, hash_redeemScript + 20);

  LL_NOTICE("redeemScriptHash=%s", HexStr(hash_redeemScript_bytes).c_str());

  std::vector<unsigned char> scriptHash;
  if (!scriptPubKey.IsPayToScriptHash(scriptHash)) {
    LL_CRITICAL("not an P2SH");
    return false;
  } else {
    LL_NOTICE("P2SH=%s", HexStr(scriptHash).c_str());
    for (int i = 0; i < 20; i++) {
      if (hash_redeemScript[i] != scriptHash[i]) {
        return false;
      }
    }
    return true;
  }
}

bytes GetScriptHash(const CScript &script) {
  std::vector<unsigned char> redeemScript_bytes = ToByteVector(script);
  unsigned char hash_redeemScript[20];

  hash160(redeemScript_bytes.data(), redeemScript_bytes.size(), hash_redeemScript);

  return std::vector<unsigned char>{hash_redeemScript, hash_redeemScript + 20};
}

const CAmount txFee = 5000; // fee that will be deducted

bool DecodeHexTx(CMutableTransaction &tx, const std::string &strHexTx, bool fTryNoWitness) {
  if (!IsHex(strHexTx))
    return false;
  vector<unsigned char> txData(ParseHex(strHexTx));
  if (fTryNoWitness) {
    CDataStream ssData(txData, SER_NETWORK, PROTOCOL_VERSION | SERIALIZE_TRANSACTION_NO_WITNESS);
    try {
      ssData >> tx;
      if (ssData.eof()) {
        return true;
      }
    }
    catch (const std::exception &) {
      // Fall through.
    }
  }
  CDataStream ssData(txData, SER_NETWORK, PROTOCOL_VERSION);
  try {
    ssData >> tx;
  }
  catch (const std::exception &) {
    return false;
  }
  return true;
}

CScript generate_redeem_script(const CPubKey user_pubkey, const CPubKey mixer_pubkey, const uint32_t lock_time) {
  CScript redeemScript;
  redeemScript << OP_IF << ToByteVector(mixer_pubkey) << OP_CHECKSIG << OP_ELSE << lock_time << OP_CHECKLOCKTIMEVERIFY
               << OP_DROP << ToByteVector(user_pubkey) << OP_CHECKSIG << OP_ENDIF;
  return redeemScript;
}

typedef vector<unsigned char> valtype;

static CScript flatten(const std::vector<valtype> &values) {
  CScript result;
  for (unsigned i = 0; i < values.size(); i++) {
    const valtype v = values[i];
    if (v.empty()) {
      result << OP_0;
    } else if (v.size() == 1 && v[0] >= 1 && v[0] <= 16) {
      result << CScript::EncodeOP_N(v[0]);
    } else {
      result << v;
    }
  }
  return result;
}

// from "policy/policy.h"
#include "script/standard.h"
static const unsigned int STANDARD_SCRIPT_VERIFY_FLAGS = MANDATORY_SCRIPT_VERIFY_FLAGS |
    SCRIPT_VERIFY_DERSIG |
    SCRIPT_VERIFY_STRICTENC |
    SCRIPT_VERIFY_MINIMALDATA |
    SCRIPT_VERIFY_NULLDUMMY |
    SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_NOPS |
    SCRIPT_VERIFY_CLEANSTACK |
    SCRIPT_VERIFY_MINIMALIF |
    SCRIPT_VERIFY_NULLFAIL |
    SCRIPT_VERIFY_CHECKLOCKTIMEVERIFY |
    SCRIPT_VERIFY_CHECKSEQUENCEVERIFY |
    SCRIPT_VERIFY_LOW_S |
    SCRIPT_VERIFY_WITNESS |
    SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM |
    SCRIPT_VERIFY_WITNESS_PUBKEYTYPE;

// from script/sign.h
void UpdateTransaction(CMutableTransaction &tx, unsigned int nIn, const SignatureData &data) {
  assert(tx.vin.size() > nIn);
  tx.vin[nIn].scriptSig = data.scriptSig;
  tx.vin[nIn].scriptWitness = data.scriptWitness;
}

CTransaction spendP2SH(const CTransaction &prevTx,
                       int nOut,
                       const CScript &redeemScript,
                       uint32_t nLockTime,
                       const CKey &privKey,
                       const CKeyID &address) {
  const CTxOut &prevOutput = prevTx.vout[nOut];
  const CScript &sigPubkey = prevOutput.scriptPubKey;

  LL_NOTICE("sigPubKey: %s", HexStr(sigPubkey).c_str());

  if (!IsValidRedeemScript(redeemScript, sigPubkey)) {
    throw invalid_argument("Invalid redeemScript");
  }

  CMutableTransaction unsignedTx;

  CTxIn vin(COutPoint(prevTx.GetHash(), nOut), CScript(), 0);
  unsignedTx.vin.push_back(vin);

  CScript newOutScriptPubkey;
  newOutScriptPubkey << OP_DUP << OP_HASH160 << ToByteVector(address) << OP_EQUALVERIFY << OP_CHECKSIG;

  CTxOut vout(prevOutput.nValue - txFee, newOutScriptPubkey);
  unsignedTx.vout.push_back(vout);

  unsignedTx.nLockTime = nLockTime;

  // generate scriptSig for input
  const CAmount &amount = prevOutput.nValue;
  SignatureData sigdata;
  std::vector<unsigned char> vchSig;
  uint256 hash = SignatureHash(redeemScript, unsignedTx, 0, SIGHASH_ALL, amount, SIGVERSION_BASE);
  privKey.Sign(hash, vchSig);
  vchSig.push_back((unsigned char) SIGHASH_ALL);

  // create complete signature
  std::vector<valtype> ret;
  ret.push_back(vchSig);
  CScript flow;
  ret.emplace_back(redeemScript.begin(), redeemScript.end());
  sigdata.scriptSig = flatten(ret);

  UpdateTransaction(unsignedTx, 0, sigdata);
  CTransaction tmpTx(unsignedTx);

  CDataStream ssTx(SER_NETWORK, PROTOCOL_VERSION);
  ssTx << tmpTx;
  LL_NOTICE("Final Tx: %s", HexStr(ssTx).c_str());
  LL_NOTICE("Refer Tx: 01000000014841c345ebe5905d40aec1ba224fc5613439a89d6229025241eaf31404a5bcab0000000074483045022100f55a6a3154fa58c0eb63fca4e9f59a866662f309c409875b5653df5cd69646a902203269b9eb060bf68e4976f8a5f98f18efa88a008058525c87b235683c27a3cfbc012a04b122cd5ab17521025c6cc70c0701405625c130a43621fe3ee35d7a8a664ffc59bb623b60d5afb657ac000000000144c29a3b000000001976a91467405e48a42e6642c7a01d20083ce80bfe5e5df588acb122cd5a");

  LL_NOTICE("tx: %s", tmpTx.ToString().c_str());

  ScriptError serror = SCRIPT_ERR_OK;
  if (!VerifyScript(vin.scriptSig,
                    sigPubkey,
                    nullptr,
                    STANDARD_SCRIPT_VERIFY_FLAGS,
                    TransactionSignatureChecker(&tmpTx, 0, amount),
                    &serror)) {
    throw runtime_error("Signing failed: " + string(ScriptErrorString(serror)));
  }

  return tmpTx;
}

#if 0
CTransaction build_settlement_tx(const map<CPubKey, CTransaction> &deposits, const CKey &sgxKey) {
  /*
   * WARNING: **This function is WIP. Do not use just yet**.
   */
  LL_NOTICE("settlement...");

  LL_NOTICE("sgx key (pub): %s", sgxKey.GetPubKey().GetID().ToString().c_str());
  int lock_time = 1000;

  CMutableTransaction unsignedSettlementTx;
  int nHashType = SIGHASH_ALL;

  for (auto &deposit : deposits) {
    const CPubKey &userKey = deposit.first;
    const CTransaction &depositTx = deposit.second;

    LL_NOTICE("user: %s with deposit %s", userKey.GetID().ToString().c_str(), depositTx.GetHash().ToString().c_str());

    CScript redeemScript = generate_redeem_script(userKey, sgxKey.GetPubKey(), lock_time);

    // TODO: fixed to use first output
    constexpr unsigned int depositOutputIndex = 1;
    const CScript &sigPubkey = depositTx.vout[depositOutputIndex].scriptPubKey;
    (void) sigPubkey;
    // TODO: uncomment this back later on
    /*
    if (!IsValidRedeemScript(redeemScript, sigPubkey)){
      LL_CRITICAL("Redeem Script hash does not match");
    }
    */
    // input
    CTxIn in(COutPoint(depositTx.GetHash(), depositOutputIndex), CScript(), 0);
    unsignedSettlementTx.vin.push_back(in);

    LL_NOTICE("input: %s", in.ToString().c_str());

    // output
    CScript newOutputScriptPubkey;
    CScript newRedeemScript = generate_redeem_script(userKey, sgxKey.GetPubKey(), lock_time + 1000);
    newOutputScriptPubkey << OP_HASH160 << GetScriptHash(newRedeemScript) << OP_EQUAL;
    // TODO: calculate amount according to the trading results
    CTxOut vout(depositTx.vout[1].nValue - txFee, newOutputScriptPubkey);
    unsignedSettlementTx.vout.push_back(vout);

    LL_NOTICE("output: %s", vout.ToString().c_str());

    // misc.
    unsignedSettlementTx.nLockTime = lock_time;

    unsigned int nIn = (unsigned int) unsignedSettlementTx.vin.size() - 1;

    // generate scriptSig for input
    const CAmount &amount = depositTx.vout[in.prevout.n].nValue;
    SignatureData sigdata;
    std::vector<unsigned char> vchSig;
    uint256 hash = SignatureHash(redeemScript, unsignedSettlementTx, nIn, nHashType, amount, SIGVERSION_BASE);
    sgxKey.Sign(hash, vchSig);
    vchSig.push_back((unsigned char) nHashType);

    // create complete signature
    std::vector<valtype> ret;
    ret.push_back(vchSig);
    CScript flow;
    flow << OP_TRUE; // take the true path
    ret.push_back(std::vector<unsigned char>(flow.begin(), flow.end()));
    ret.push_back(std::vector<unsigned char>(redeemScript.begin(), redeemScript.end()));
    sigdata.scriptSig = flatten(ret);

    UpdateTransaction(unsignedSettlementTx, nIn, sigdata);
    ScriptError serror = SCRIPT_ERR_OK;

    CTransaction tmpTx(unsignedSettlementTx);

    CDataStream ssTx(SER_NETWORK, PROTOCOL_VERSION);
    ssTx << tmpTx;
    LL_NOTICE("Unsigned TX: %s", HexStr(ssTx).c_str());

    if (!VerifyScript(in.scriptSig,
                      depositTx.vout[in.prevout.n].scriptPubKey,
                      nullptr,
                      STANDARD_SCRIPT_VERIFY_FLAGS,
                      TransactionSignatureChecker(&tmpTx, nIn, amount),
                      &serror)) {
      LL_CRITICAL("Signing failed: %s", ScriptErrorString(serror));
      continue;
    }

  }

  return CTransaction(unsignedSettlementTx);
}
#endif

#include <utility>

CScript generate_cltv_script(uint32_t cltv, const CKey &privKey) {
  CScript redeemScript;
  redeemScript << cltv << OP_CHECKLOCKTIMEVERIFY << OP_DROP << ToByteVector(privKey.GetPubKey()) << OP_CHECKSIG;
  LL_NOTICE("redeemscript %s", HexStr(redeemScript).c_str());

  return redeemScript;
}

#include "base58.h"

void test_bitcoin_transaction() {
  const string sgxPrivKey = "cURgah32X7tNqK9NCkpXVVd4bbocWm3UjgwyAGpdVfxicAZynLs5";
  const uint32_t cltvTimeout = 1523393201;

  // txid = 2ac4a2a3a31d873df3119e84cda01c828c58296ebbd47b6a99f6506029889e43
  const string rawPrevTxP2SH =
      "02000000000102439e88296050f6996a7bd4bb6e29588c821ca0cd849e11f33d871da3a3a2c42a00000000171600141a70c43931b3a5a8f1dac0ace75685e337ad7a2dfeffffffe6d4145830b185209d83cca12d3b23411900cff541afd9b5cd973261a8f7e64c00000000171600149f2c6857ee702fca7100af7a20248014cec71e02feffffff0200ca9a3b0000000017a914d5a4f94120e08c57890a808178cfcf3cc6838c95871c5cf5050000000017a914e7c424079d69f0bd6f724667952950827c8c9bf48702483045022100d47dfdbf311f3793f1b3a3493794066b3bf514d1cc605e61bfcb3424eefddd28022078870b49064aa430328bd011fe30c1dcf1c1ea30c58d89f63b2c8bc45114a55a01210357d7cb2f73a55aad7e655658a058e3505cdc843ee9deae32258156518da137ac02483045022100976d5d4e488a1e9eed828a663bf3de44fc52a777cc66676196d3adff189d256502207204a98a58ca22e4e026ffe1546d1ebeadb7b9568a1d7979fe330c2e98f07df9012102cb0331b66bc60f3ca33b4f1f1ada0ec90425c8e4c0a2f9b0230b7c28934f903585000000";

  // reference spending tx
  // 0100000001439e88296050f6996a7bd4bb6e29588c821ca0cd849e11f33d871da3a3a2c42a0100000073473044022007d379a2f344929aa9abed71b53b82958560bd4256bc2ba844e58453a99720ed02207609d0286451a4640fb69448aa4fa7df8438c0dab727fc238c005fce00d1f669012a0439f4cc5ab17521025c6cc70c0701405625c130a43621fe3ee35d7a8a664ffc59bb623b60d5afb657ac000000000144fb154e0200000017a91422d7fe2b01d33824e3bd5086aeb762d62b3e75828739f4cc5a

  // goal: construct a tx that spends rawPrevTxP2SH
  ECC_Start();
  SelectParams(CBaseChainParams::REGTEST);

  try {
    CBitcoinSecret secret;
    if (!secret.SetString(sgxPrivKey)) {
      throw runtime_error("cannot parse private key");
    }
    CKey sgxKey = secret.GetKey();

    CMutableTransaction _prevTx;
    DecodeHexTx(_prevTx, rawPrevTxP2SH, false);
    CTransaction prevTx(_prevTx);


    CBitcoinAddress toAddress;
    toAddress.Set(sgxKey.GetPubKey().GetID());

    LL_NOTICE("spending -> %s", toAddress.ToString().c_str());

    CTransaction t = spendP2SH(
        prevTx,
        0,
        generate_cltv_script(cltvTimeout, sgxKey),
        cltvTimeout,
        sgxKey, secret.GetKey().GetPubKey().GetID());
  }
  catch (const std::exception &e) {
    LL_CRITICAL("error happened: %s", e.what());
  }
  catch (...) {
    LL_CRITICAL("unknown error happened");
  }

  ECC_Stop();
}
