#include "settle.h"
#include <bitcoin/script/sign.h>
#include "bitcoin/policy/policy.h"
#include "bitcoin/streams.h"
#include "bitcoin/utilstrencodings.h"
#include "bitcoin_helpers.h"

using std::vector;

void DepositParams::_gen_deposit_redeemScript()
{
  auto exchScriptPubkey = GetScriptForDestination(exchPubkey.GetID());
  auto userScriptPubkey = GetScriptForDestination(userPubkey.GetID());
  this->_redeemScript << OP_IF;
  this->_redeemScript += exchScriptPubkey;
  this->_redeemScript << OP_ELSE << locktime << OP_CHECKLOCKTIMEVERIFY
                      << OP_DROP;
  this->_redeemScript += userScriptPubkey;
  this->_redeemScript << OP_ENDIF;
}

CScript DepositParams::spend_redeemScript(
    Action action,
    const CKey &privKey,
    const CMutableTransaction &unsignedTx,
    uint32_t nIn) const
{
  CScript branch;
  switch (action) {
    //! when user withdraws the ELSE branch is taken
    case Action::Withdrawal:
      branch << OP_FALSE;
      break;
    case Action::Settlement:
      branch << OP_TRUE;
  }

  // note: amount is set to zero since it's not used in SIGVERSION_BASE anyway.
  auto sighash = SignatureHash(
      deposit_redeemScript(), unsignedTx, nIn, SIGHASH_ALL, 0, SIGVERSION_BASE);

  std::vector<unsigned char> vchSig;
  privKey.Sign(sighash, vchSig);
  vchSig.push_back((unsigned char)SIGHASH_ALL);

  auto s =
      (CScript() << ToByteVector(vchSig) << ToByteVector(privKey.GetPubKey())) +
      (branch << ToByteVector(deposit_redeemScript()));
  return s;
}

CTransaction settle_to_single_addr(
    const CKey &exch_seckey,
    const vector<Deposit> &deposits,
    const CBitcoinAddress &addr,
    uint32_t nlocktime) noexcept(false)
{
  CMutableTransaction unsigned_tx;

  CAmount sum_in = 0;

  // populate all of the inputs
  for (const auto &d : deposits) {
    if (!d.Validate()) {
      throw std::runtime_error("invalid_script");
    }
    sum_in += d.PrevOut().nValue;
    // note: cltv is disabled by setting all input's nSequence to 0xFFFFFFFF
    // so we set it to 0 to enable CLTV
    unsigned_tx.vin.emplace_back(COutPoint(d.Txid(), d.NOut()), CScript(), 0);
  }

  // FIXME: use estimatesmartfee instead
  auto tx_size = 4 + 2 + deposits.size() * 153 + 1 + 34 + 4;
  CFeeRate fixed_rate(10000);
  CAmount fees = fixed_rate.GetFee(tx_size);
  LL_NOTICE("fees = %d", fees);

  CAmount amount = sum_in - fees;

  // populate the (only) output
  unsigned_tx.vout.emplace_back(amount, GetScriptForDestination(addr.Get()));
  unsigned_tx.nLockTime = nlocktime;

  assert(deposits.size() == unsigned_tx.vin.size());

  // sign all the inputs
  for (uint32_t i = 0; i < deposits.size(); i++) {
    auto sigScript = deposits[i].Params().spend_redeemScript(
        Settlement, exch_seckey, unsigned_tx, i);
    unsigned_tx.vin[i].scriptSig = sigScript;
  }

  auto t = CTransaction(unsigned_tx);

  // verify the script
  auto globalHandle = std::unique_ptr<ECCVerifyHandle>(new ECCVerifyHandle());
  ScriptError serror = SCRIPT_ERR_OK;
  for (uint32_t i = 0; i < deposits.size(); i++) {
    if (!VerifyScript(
            t.vin[i].scriptSig,
            deposits[i].PrevOut().scriptPubKey,
            nullptr,
            STANDARD_SCRIPT_VERIFY_FLAGS,
            TransactionSignatureChecker(&t, i, 0),
            &serror)) {
      throw std::runtime_error(ScriptErrorString(serror));
    }
  }

  return t;
}

//! for each deposit (V, locktime), a new output is (V + delta, locktime + T) is created.
//! \param exchSecretkey exchange's secret key
//! \param feePayment where we draw the fees
//! \param deposits a vector of current active deposits
//! \param balanceDelta a vector of amounts (signed) denoting balance adjustment
//! \param lockTimeDelta T in the above formula
//! \param nLockTime nLockTime for the output transaction
//! \param feeRate feeRate to use when creating the output transaction
//! \return a settlement transaction
CTransaction settle(
    const CKey &exchSecretkey,
    const FeePayment &feePayment,
    const vector<Deposit> &deposits,
    const vector<int64_t> &balanceDelta,
    uint32_t lockTimeDelta,
    uint32_t nLockTime,
    const CFeeRate &feeRate) noexcept(false)
{
  // assert that balance delta sums up to zero
  MUST_TRUE(deposits.size() == balanceDelta.size());
  int64_t delta_sum = 0;
  for (auto delta : balanceDelta) {
    delta_sum += delta;
  }

  if (0 != delta_sum) {
    throw std::invalid_argument("delta doesn't sum to zero");
  }

  // calculate the transaction fees
  // FIXME static size estimation
  auto tx_size = 4 + 2 + 2 + deposits.size() * (153 + 34) + 4;
  CAmount fees = feeRate.GetFee(tx_size);
  LL_NOTICE("fees = %d", fees);

  if (fees > feePayment.prevOut().nValue) {
    throw std::invalid_argument("insufficient fee payment supplied");
  }

  CAmount fee_refund = feePayment.prevOut().nValue - fees;

  // start building the settlement transaction
  CMutableTransaction unsigned_tx;

  // populate all of the inputs
  for (int i = 0; i < deposits.size(); i++) {
    const auto &d = deposits[i];
    if (!d.Validate()) {
      throw std::runtime_error("invalid_script");
    }

    // assert solvent and prevent overflow
    MUST_TRUE(d.PrevOut().nValue + balanceDelta[i] >= 0);

    // note: cltv is disabled by setting all input's nSequence to 0xFFFFFFFF
    // so we set it to 0 to enable CLTV
    unsigned_tx.vin.emplace_back(COutPoint(d.Txid(), d.NOut()), CScript(), 0);
  }

  // add fee payment UTXO
  unsigned_tx.vin.emplace_back(feePayment.ToOutPoint(), CScript(), 0);

  // populate the outputs
  for (int i = 0; i < deposits.size(); i++) {
    const auto &deposit = deposits[i];
    auto new_param = deposit.Params().UpdateLockTime(lockTimeDelta);

    auto new_amount = deposit.PrevOut().nValue + balanceDelta[i];
    if (new_amount == 0) {
      continue;
    }

    unsigned_tx.vout.emplace_back(new_amount, new_param.scriptPubkey());
  }

  // add fee refund
  if (fee_refund > 0) {
    unsigned_tx.vout.emplace_back(
        fee_refund, GetScriptForDestination(exchSecretkey.GetPubKey().GetID()));
  }

  // set the locktime
  unsigned_tx.nLockTime = nLockTime;

  // sign all the inputs
  for (uint32_t i = 0; i < deposits.size(); i++) {
    auto sigScript = deposits[i].Params().spend_redeemScript(
        Settlement, exchSecretkey, unsigned_tx, i);
    unsigned_tx.vin[i].scriptSig = sigScript;
  }

  // sign the fee payment input
  if (!feePayment.Sign(exchSecretkey, unsigned_tx, unsigned_tx.vin.size())) {
    throw std::invalid_argument("can't sign the fee payment output");
  }

  auto t = CTransaction(unsigned_tx);

  // verify the script
  auto globalHandle = std::unique_ptr<ECCVerifyHandle>(new ECCVerifyHandle());
  ScriptError serror = SCRIPT_ERR_OK;
  for (uint32_t i = 0; i < deposits.size(); i++) {
    if (!VerifyScript(
            t.vin[i].scriptSig,
            deposits[i].PrevOut().scriptPubKey,
            nullptr,
            STANDARD_SCRIPT_VERIFY_FLAGS,
            TransactionSignatureChecker(&t, i, 0),
            &serror)) {
      throw std::runtime_error(ScriptErrorString(serror));
    }
  }

  return t;
}

bool test_settlement()
{
  SelectParams(CBaseChainParams::REGTEST);
  ECC_Start();

  bool ret = true;
  try {
    CBitcoinSecret exch_secret(seckey_from_str("exch"));

    vector<CBitcoinSecret> users;
    users.emplace_back(seckey_from_str("alice"));
    users.emplace_back(seckey_from_str("bob"));

    const auto &exch_pubKey = exch_secret.GetKey().GetPubKey();

    uint32_t nlocktime = 1000000;  // 1 million block
    vector<DepositParams> params;
    for (const auto &user : users) {
      params.emplace_back(user.GetKey().GetPubKey(), exch_pubKey, nlocktime);
    }

    for (const auto &p : params) {
      LL_NOTICE("please deposit at: %s", p.address().ToString().c_str());
    }

    auto _deposit_tx_hex =
        "020000000125c60a56c9fd0e805bfdd783729d939b81d857954c410c854c8b8f94894e"
        "c94a0000000048473044022010ee74bbeddfdfc7573da4919b7f514f2112d765f909e0"
        "146775cde0232778c40220710158c1f8ceb08bdbb84a6e79b4eef794dc8bd3c2de3e05"
        "6a91b94c6a17c3ea01fdffffff03e44cd0b20000000017a91422132fe15114d4742f5f"
        "25dc2df43c110941a8378700ca9a3b0000000017a914c0e6d37a01c9999d88b4dc252a"
        "39e571bea1603a8700ca9a3b0000000017a914e7f1469b5d6f65bcce9c91be45e519ba"
        "23088aa98794000000";

    CMutableTransaction _deposit;
    DecodeHexTx(_deposit, _deposit_tx_hex, false);
    CTransaction deposit_tx(_deposit);

    Deposit alice_deposit(params[0], deposit_tx, 1);
    Deposit bob_deposit(params[1], deposit_tx, 2);

    LL_CRITICAL(
        "Alice's redeemScript: %s",
        HexStr(
            params[0].deposit_redeemScript().begin(),
            params[0].deposit_redeemScript().end())
            .c_str());

    CBitcoinAddress target("2NCoX4m42XUEypfdaWo8m58s1hiMu55gbVv");

    vector<Deposit> deposits;
    deposits.push_back(alice_deposit);
    deposits.push_back(bob_deposit);

    // 158 is the latest block number so that this tx can be included right away
    auto t = settle_to_single_addr(exch_secret.GetKey(), deposits, target, 158);

    // dump the hex
    CDataStream ssTx(SER_NETWORK, PROTOCOL_VERSION);
    ssTx << t;

    LL_NOTICE("Final raw tx: %s", HexStr(ssTx).c_str());
    LL_NOTICE("Interpreted as: %s", t.ToString().c_str());
  }
  CATCHALL_AND(ret = false)

  ECC_Stop();
  return ret;
}

bool test_settle_all() { return true; }