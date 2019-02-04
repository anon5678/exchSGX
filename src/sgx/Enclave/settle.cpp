#include "settle.h"

#include <initializer_list>

#include "bitcoin/policy/policy.h"
#include "bitcoin/script/sign.h"
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
    sum_in += d.prevOut().nValue;
    // note: cltv is disabled by setting all input's nSequence to 0xFFFFFFFF
    // so we set it to 0 to enable CLTV
    unsigned_tx.vin.emplace_back(COutPoint(d.txid(), d.nOut()), CScript(), 0);
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
    auto sigScript = deposits[i].params().spend_redeemScript(
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
            deposits[i].prevOut().scriptPubKey,
            nullptr,
            STANDARD_SCRIPT_VERIFY_FLAGS,
            TransactionSignatureChecker(&t, i, 0),
            &serror)) {
      throw std::runtime_error(ScriptErrorString(serror));
    }
  }

  return t;
}

//! generate a cancellation transaction by spending the feePayment UTXO (to the same scriptPubkey)
//! \param feePayment UTXO to spend
//! \param exch exchange object (has the secret)
//! \param feeRate
//! \param nLockTime
//! \return
CTransaction _generate_cancellation_tx(
    const FeePayment &feePayment,
    const Exchange &exch,
    const CFeeRate &feeRate,
    uint32_t nLockTime)
{
  // calculate the transaction fees
  // TODO we need a smarter size estimation
  size_t tx_size = 4 + 2 + 2 + 153 + 34 + 4;
  CAmount fees = feeRate.GetFee(tx_size);
  LL_NOTICE("fees = %d", fees);

  if (fees > feePayment.prevOut().nValue) {
    throw std::invalid_argument("insufficient fee payment supplied");
  }

  CAmount fee_refund = feePayment.prevOut().nValue - fees;
  LL_NOTICE("fee_refund = %d", fee_refund);

  // start building the settlement transaction
  CMutableTransaction unsigned_tx;

  // add fee payment UTXO
  unsigned_tx.vin.emplace_back(feePayment.ToOutPoint(), CScript(), 0);
  LL_DEBUG("done adding inputs");

  // set the locktime
  unsigned_tx.nLockTime = nLockTime;

  LL_DEBUG("done adding outputs");

  // add fee refund
  if (fee_refund > 0) {
    unsigned_tx.vout.emplace_back(fee_refund, exch.scriptPubkey());
  }

  // sign the fee payment input
  if (!feePayment.Sign(exch.privKey(), unsigned_tx, 0)) {
    throw std::invalid_argument("can't sign the fee payment output");
  }

  LL_DEBUG("done signing");
  auto tx_cancellation = CTransaction(unsigned_tx);

  // verify the script
  ScriptError serror = SCRIPT_ERR_OK;
  if (!VerifyScript(
          tx_cancellation.vin[0].scriptSig,
          feePayment.prevOut().scriptPubKey,
          nullptr,
          STANDARD_SCRIPT_VERIFY_FLAGS,
          TransactionSignatureChecker(&tx_cancellation, 0, 0),
          &serror)) {
    throw std::runtime_error(ScriptErrorString(serror));
  } else {
    LL_DEBUG("script verifies");
  }

  return tx_cancellation;
}

//! for each deposit (V, locktime), a new output is (V + delta, locktime + T) is created.
//! \param newDeposits info (e.g. redeemScripts) for new outputs
//! \param exchSecretkey exchange's secret key
//! \param feePayment where we draw the fees
//! \param deposits a vector of current active deposits
//! \param balanceDelta a vector of amounts (signed) denoting balance adjustment
//! \param lockTimeDelta T in the above formula
//! \param nLockTime nLockTime for the output transaction
//! \param feeRate feeRate to use when creating the output transaction
//! \return a settlement transaction and a cancellation transaction
std::pair<CTransaction, CTransaction>
generate_settlement_tx_bitcoin_or_litecoin(
    vector<DepositParams> &newDeposits,
    const Exchange &exch,
    const FeePayment &feePayment,
    const vector<Deposit> &deposits,
    const vector<int64_t> &balanceDelta,
    uint32_t lockTimeDelta,
    uint32_t nLockTime,
    const CFeeRate &feeRate) noexcept(false)
{
  // set up the secp256k1 context (which will get freed automatically)
  auto _ctx = std::unique_ptr<ECCVerifyHandle>(new ECCVerifyHandle());

  // assert that balance delta sums up to zero
  MUST_TRUE(deposits.size() == balanceDelta.size());

  //
  int64_t delta_sum = 0;
  for (auto delta : balanceDelta) {
    delta_sum += delta;
  }

  MUST_TRUE_OR(0 == delta_sum, "delta doesn't sum to zero");

  // calculate the transaction fees
  // TODO we need a smarter size estimation
  auto tx_size = 4 + 2 + 2 + deposits.size() * (153 + 34) + 4;
  CAmount fees = feeRate.GetFee(tx_size);
  LL_NOTICE("fees = %d", fees);

  if (fees > feePayment.prevOut().nValue) {
    throw std::invalid_argument("insufficient fee payment supplied");
  }

  CAmount fee_refund = feePayment.prevOut().nValue - fees;
  LL_NOTICE("fee_refund = %d", fee_refund);

  // start building the settlement transaction
  CMutableTransaction unsigned_tx;

  // populate all of the inputs
  for (int i = 0; i < deposits.size(); i++) {
    const auto &d = deposits[i];
    if (!d.Validate()) {
      throw std::runtime_error("invalid_script");
    }

    // assert solvent and prevent overflow
    MUST_TRUE(d.prevOut().nValue + balanceDelta[i] >= 0);

    // note: cltv is disabled by setting all input's nSequence to 0xFFFFFFFF
    // so we set it to 0 to enable CLTV
    unsigned_tx.vin.emplace_back(COutPoint(d.txid(), d.nOut()), CScript(), 0);
  }

  // add fee payment UTXO
  unsigned_tx.vin.emplace_back(feePayment.ToOutPoint(), CScript(), 0);
  size_t fee_payment_idx = unsigned_tx.vin.size() - 1;

  LL_DEBUG("done adding inputs");

  // populate the outputs
  for (int i = 0; i < deposits.size(); i++) {
    const auto &deposit = deposits[i];
    auto new_param = deposit.params().UpdateLockTime(lockTimeDelta);
    auto new_amount = deposit.prevOut().nValue + balanceDelta[i];
    if (new_amount == 0) {
      continue;
    }

    unsigned_tx.vout.emplace_back(new_amount, new_param.scriptPubkey());
    // record the new deposit
    newDeposits.push_back(new_param);
  }

  // set the locktime
  unsigned_tx.nLockTime = nLockTime;

  LL_DEBUG("done adding outputs");

  // add fee refund
  if (fee_refund > 0) {
    unsigned_tx.vout.emplace_back(fee_refund, exch.scriptPubkey());
  }

  // sign all the inputs
  for (uint32_t i = 0; i < deposits.size(); i++) {
    auto sigScript = deposits[i].params().spend_redeemScript(
        Settlement, exch.privKey(), unsigned_tx, i);
    unsigned_tx.vin[i].scriptSig = sigScript;
  }

  LL_DEBUG("done signing deposits");

  // sign the fee payment input
  if (!feePayment.Sign(exch.privKey(), unsigned_tx, fee_payment_idx)) {
    throw std::invalid_argument("can't sign the fee payment output");
  }

  LL_DEBUG("done signing");
  auto tx_settlement = CTransaction(unsigned_tx);

  // verify the script
  ScriptError serror = SCRIPT_ERR_OK;
  for (uint32_t i = 0; i < deposits.size(); i++) {
    if (!VerifyScript(
            tx_settlement.vin[i].scriptSig,
            deposits[i].prevOut().scriptPubKey,
            nullptr,
            STANDARD_SCRIPT_VERIFY_FLAGS,
            TransactionSignatureChecker(&tx_settlement, i, 0),
            &serror)) {
      throw std::runtime_error(ScriptErrorString(serror));
    } else {
      LL_DEBUG("script verifies");
    }
  }

  // create the cancellation transaction
  auto tx_cancellation =
      _generate_cancellation_tx(feePayment, exch, feeRate, nLockTime);

  return std::make_pair(tx_settlement, tx_cancellation);
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

    uint32_t depositExpiration = 1000000;  // 1 million block
    vector<DepositParams> params;
    for (const auto &user : users) {
      params.emplace_back(
          user.GetKey().GetPubKey(), exch_pubKey, depositExpiration);
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

void _do_test_settlement_all(
    const std::string &user_deposit_tx_hex,
    const std::string &exchamge_deposit_tx_hex,
    vector<uint32_t> user_deposit_nout,
    uint32_t exchange_deposit_nout,
    const vector<DepositParams> &params,
    const Exchange &exch)
{
  CMutableTransaction _user_deposit;
  DecodeHexTx(_user_deposit, user_deposit_tx_hex, false);
  CTransaction user_deposit_tx(_user_deposit);

  CMutableTransaction _exch_deposit;
  DecodeHexTx(_exch_deposit, exchamge_deposit_tx_hex, false);
  CTransaction exch_deposit_tx(_exch_deposit);

  vector<Deposit> currentDeposits;

  // load user deposit
  for (auto i = 0; i < user_deposit_nout.size(); i++) {
    currentDeposits.emplace_back(
        params[i], user_deposit_tx, user_deposit_nout[i]);
  }

  // load fee payment transaction
  FeePayment feePayment(exch_deposit_tx, exchange_deposit_nout);

  // simulate balance delta
  vector<int64_t> balance_delta = {0, 0, 0, 0};

  // lockTime
  uint32_t nLockTime = 0;  // this concrete value doesn't matter as long as
  // nLockTime <= blockcount
  CFeeRate fixedRate(10000);  // FIXME using a static 10000 Satoshi / KB

  // newDeposits is generated
  vector<DepositParams> newDeposits;
  auto tx_pair = generate_settlement_tx_bitcoin_or_litecoin(
      newDeposits,
      exch,
      feePayment,
      currentDeposits,
      balance_delta,
      100,  // increase the time lock with 100 blocks
      nLockTime,
      fixedRate);

  for (const auto &nd : newDeposits) {
    LL_NOTICE(
        "new redeemScript: %s",
        HexStr(
            nd.deposit_redeemScript().begin(), nd.deposit_redeemScript().end())
            .c_str());
  }

  {
    // dump the hex
    CDataStream ss(SER_NETWORK, PROTOCOL_VERSION);
    ss << tx_pair.first;

    LL_NOTICE("settlement tx: %s", tx_pair.first.ToString().c_str());
    LL_NOTICE("settlement tx (raw) : %s", HexStr(ss).c_str());
  }

  {
    // dump the hex
    CDataStream ss(SER_NETWORK, PROTOCOL_VERSION);
    ss << tx_pair.second;

    LL_NOTICE("cancellation tx: %s", tx_pair.second.ToString().c_str());
    LL_NOTICE("cancellation tx (raw) : %s", HexStr(ss).c_str());
  }
}

bool test_settle_all()
{
  SelectParams(CBaseChainParams::TESTNET);
  ECC_Start();

  bool ret = true;
  try {
    CBitcoinSecret exch_secret(seckey_from_str("exch"));

    // simulate a bunch of users
    vector<CBitcoinSecret> users;
    for (auto name : {"alice", "bob", "carol", "david"}) {
      users.emplace_back(seckey_from_str(name));
    }

    // simulate the exchange
    Exchange exch(exch_secret.GetKey());
    const auto &exch_pubkey = exch.pubKey();
    LL_NOTICE("fee address: %s", exch.P2PKHAddress().ToString().c_str());

    uint32_t depositTimeLock = 1000000;
    vector<DepositParams> params;
    for (const auto &u : users) {
      params.emplace_back(u.GetKey().GetPubKey(), exch_pubkey, depositTimeLock);
    }

    for (const auto &p : params) {
      LL_NOTICE("user address: %s", p.address().ToString().c_str());
    }

    // deposit address are:
    // fee: muEPF2wfm1QdLy3LKocBQiW8g73WpzFq72
    // users: alice, bob, ..., david:
    //  2NAqCFC8FazvtUzGv23reB9kQyR9JBW48PB
    //  2NEPd7jWr4mFw2iGeVQvzn5YMZrwL7R7esH
    //  2MvdHzi7sxRbJTwjcH7wMT7z5GDpiq7ktfJ
    //  2MuAaNqaBaWTKFPq5CENWmhd58u7zJQLpnG

    {
#include "test_data/settlement_bitcoin"
      _do_test_settlement_all(
          __user_deposit_tx_hex,
          __exch_deposit_tx_hex,
          __user_deposit_tx_out,
          __exchange_deposit_nout,
          params,
          exch);
    }

    {
#include "test_data/settlement_litecoin"
      _do_test_settlement_all(
          __user_deposit_tx_hex,
          __exch_deposit_tx_hex,
          __user_deposit_tx_out,
          __exchange_deposit_nout,
          params,
          exch);
    }
  }
  CATCHALL_AND(ret = false)

  ECC_Stop();
  return ret;
}
