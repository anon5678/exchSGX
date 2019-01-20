#include "state.h"
#include "pprint.h"
#include "log.h"
#include "bitcoin/crypto/sha256.h"
#include "bitcoin/hash.h"

#include "bitcoin_helpers.h"

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

CTransaction spendP2SH(const OutPoint &outpoint,
                       CAmount fee,
                       const CScript &redeemScript,
                       uint32_t nLockTime,
                       const CKey &privKey,
                       const CBitcoinAddress &address) {
  const CTxOut &prevOutput = outpoint.GetTxOut();
  const CScript &scriptPubKey = prevOutput.scriptPubKey;

  if (!IsValidRedeemScript(redeemScript, scriptPubKey)) {
    LL_DEBUG("sigPubKey: %s", HexStr(scriptPubKey).c_str());
    throw invalid_argument("Invalid redeemScript");
  } else {
    LL_DEBUG("redeemScript matches with sigPubkey");
  }

  CMutableTransaction unsignedTx;

  // use the input
  unsignedTx.vin.emplace_back(outpoint.ToCOutPoint(), CScript(), 0);

  // construct the output script
  auto newOutScriptPubkey = GetScriptForDestination(address.Get());

  const CAmount amount = prevOutput.nValue - fee;

  unsignedTx.vout.emplace_back(amount, newOutScriptPubkey);
  unsignedTx.nLockTime = nLockTime;

  // Generate scriptSig to spend input.
  std::vector<unsigned char> vchSig;
  uint256 hash = SignatureHash(redeemScript, unsignedTx, 0, SIGHASH_ALL, 0, SIGVERSION_BASE);

  auto globalHandle = unique_ptr<ECCVerifyHandle>(new ECCVerifyHandle());

  privKey.Sign(hash, vchSig);
  if (!privKey.GetPubKey().Verify(hash, vchSig)) {
    // sanity check
    throw runtime_error("Sign() generated an invalid signature");
  }

  /// push the SIGHASH_ALL byte.
  vchSig.push_back((unsigned char) SIGHASH_ALL);

  // create complete signature.
  auto sigScript = CScript() << ToByteVector(vchSig) << ToByteVector(redeemScript);
  // embed the signature into the transaction.
  unsignedTx.vin[0].scriptSig = sigScript;

  // create an immutable transaction and serialize it
  CTransaction tmpTx(unsignedTx);

  // verify the script
  ScriptError serror = SCRIPT_ERR_OK;
  if (!VerifyScript(tmpTx.vin[0].scriptSig,
                    scriptPubKey,
                    nullptr,
                    STANDARD_SCRIPT_VERIFY_FLAGS,
                    TransactionSignatureChecker(&tmpTx, 0, amount),
                    &serror)) {
    throw runtime_error("Signing failed: " + string(ScriptErrorString(serror)));
  } else {
    LL_NOTICE("success.");
  }

  return tmpTx;
}

#include <utility>
#include "bitcoin/base58.h"

void test_bitcoin_transaction() {
  /// import an UTXO used for testing
#include "cltvtest"

  // goal: construct a tx that spends rawPrevTxP2SH
  SelectParams(CBaseChainParams::REGTEST);
  ECC_Start();

  try {
    CBitcoinSecret secret;
    if (!secret.SetString(sgxPrivKey)) {
      throw runtime_error("cannot parse private key");
    }
    CKey sgxKey = secret.GetKey();
    auto sgxPubkey = sgxKey.GetPubKey();

    CMutableTransaction _prevTx;
    DecodeHexTx(_prevTx, rawPrevTxP2SH, false);
    CTransaction prevTx(_prevTx);

    LL_NOTICE("Successfully loaded the testing UTXO");
    LL_NOTICE("%s", prevTx.ToString().c_str());

    CBitcoinAddress toAddress;
    toAddress.Set(sgxKey.GetPubKey().GetID());
    LL_NOTICE("Trying to spend to address %s", toAddress.ToString().c_str());

    auto script = generate_simple_cltv_script(sgxPubkey, cltvTimeout);
    LL_NOTICE("Redeem script (hex) is %s", HexStr(script).c_str());

    CTransaction t = spendP2SH(
        OutPoint(prevTx, nIn),
        static_cast<CAmount>(1980),
        script,
        cltvTimeout,
        sgxKey, CBitcoinAddress(sgxPubkey.GetID()));

    // dump the hex
    CDataStream ssTx(SER_NETWORK, PROTOCOL_VERSION);
    ssTx << t;

    LL_NOTICE("Final raw tx: %s", HexStr(ssTx).c_str());
    LL_NOTICE("Interpreted as: %s", t.ToString().c_str());
  }
  CATCH_STD_AND_ALL_NO_RET
  ECC_Stop();
}
