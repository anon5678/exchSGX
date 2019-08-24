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
  LL_LOG("fees = %d", fees);

  if (fees > feePayment.prevOut().nValue) {
    throw std::invalid_argument("insufficient fee payment supplied");
  }

  CAmount fee_refund = feePayment.prevOut().nValue - fees;
  LL_LOG("fee_refund = %d", fee_refund);

  // start building the settlement transaction
  CMutableTransaction unsigned_tx;

  // add fee payment UTXO
  unsigned_tx.vin.emplace_back(feePayment.ToOutPoint(), CScript(), 0);
  LL_LOG("done adding inputs");

  // set the locktime
  unsigned_tx.nLockTime = nLockTime;

  LL_LOG("done adding outputs");

  // add fee refund
  if (fee_refund > 0) {
    unsigned_tx.vout.emplace_back(fee_refund, exch.scriptPubkey());
  }

  // sign the fee payment input
  if (!feePayment.Sign(exch.privKey(), unsigned_tx, 0)) {
    throw std::invalid_argument("can't sign the fee payment output");
  }

  LL_LOG("done signing");
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
    LL_LOG("script verifies");
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
  LL_LOG("fees = %d", fees);

  if (fees > feePayment.prevOut().nValue) {
    throw std::invalid_argument("insufficient fee payment supplied");
  }

  CAmount fee_refund = feePayment.prevOut().nValue - fees;
  LL_LOG("fee_refund = %d", fee_refund);

  // start building the settlement transaction
  CMutableTransaction unsigned_tx;

  // populate all of the inputs
  for (size_t i = 0; i < deposits.size(); i++) {
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

  LL_LOG("done adding inputs");

  // populate the outputs
  for (size_t i = 0; i < deposits.size(); i++) {
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

  LL_LOG("done adding outputs");

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

  LL_LOG("done signing deposits");

  // sign the fee payment input
  if (!feePayment.Sign(exch.privKey(), unsigned_tx, fee_payment_idx)) {
    throw std::invalid_argument("can't sign the fee payment output");
  }

  LL_LOG("done signing");
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
      LL_LOG("script verifies");
    }
  }

  // create the cancellation transaction
  auto tx_cancellation =
      _generate_cancellation_tx(feePayment, exch, feeRate, nLockTime);

  return std::make_pair(tx_settlement, tx_cancellation);
}

std::pair<CTransaction, CTransaction> _do_test_settlement_all(
    //const std::string &user_deposit_tx_hex,
    int num,
    unsigned char* deposit_tx_hex, 
    size_t* size,
    uint16_t* vout)
    //uint32_t* deposit_nout,
    //uint32_t exchange_deposit_nout,
    //const vector<DepositParams> &params,
    //const Exchange &exch)
{
        CBitcoinSecret exch_secret(seckey_from_str("exch"));
        // simulate the exchange
        Exchange exch(exch_secret.GetKey());
        const auto &exch_pubkey = exch.pubKey();
        LL_NOTICE(
                "sgx public key: %s",
                HexStr(exch.pubKey().begin(), exch.pubKey().end()).c_str());
        LL_NOTICE("fee address: %s", exch.P2PKHAddress().ToString().c_str());

        uint32_t depositTimeLock = 1000000;
        vector<DepositParams> params;

#ifdef GETKEYS
        for (auto i = 0; i < 6000; ++i) {
            auto name = "User" + std::to_string(i);
            CBitcoinSecret secret(seckey_from_str(name));
            auto u = DepositParams(name, secret.GetKey().GetPubKey(), exch_pubkey, depositTimeLock);
            LL_NOTICE("%s", u.address().ToString().c_str());
        }
#endif
        
        for (auto i = 0; i < num; ++i) {
            auto name = "User" + std::to_string(i);
            CBitcoinSecret secret(seckey_from_str(name));
            params.emplace_back(
                    name, secret.GetKey().GetPubKey(), exch_pubkey, depositTimeLock);

            //auto u = params.back();
            //LL_NOTICE("%s", u.ToString().c_str());
        }

        size_t tmp = 0;
        CMutableTransaction _exch_deposit;
        DecodeHexTx(_exch_deposit, 
                std::string(reinterpret_cast<char *>(deposit_tx_hex), size[0]), false);
        tmp += size[0];
        CTransaction exch_deposit_tx(_exch_deposit);

        CMutableTransaction _user_deposit[num];
        for (int i = 1; i < num + 1; ++i) {
            DecodeHexTx(_user_deposit[i - 1], 
                    std::string(reinterpret_cast<char *>(deposit_tx_hex + tmp), size[i]), false);
            tmp += size[i];
            //CTransaction user_deposit_tx(_user_deposit[i - 1]);
        }

        vector<Deposit> currentDeposits;

        // load user deposit
        for (size_t i = 0; i < num; i++) {//user_deposit_nout.size(); i++) {
            currentDeposits.emplace_back(
                    params[i], CTransaction(_user_deposit[i]), vout[i + 1]);//user_deposit_nout[i]);
        }

        // load fee payment transaction
        FeePayment feePayment(exch_deposit_tx, vout[0]);//exchange_deposit_nout);

        // simulate balance delta
        vector<int64_t> balance_delta;
        for (auto i = 0; i < num / 2; ++i) {
            balance_delta.push_back(-1);
        }
        if (num % 2 == 1) {
            balance_delta.push_back(0);
        }
        for (auto i = 0; i < num / 2; ++i) {
            balance_delta.push_back(1);
        }

        // lockTime
        uint32_t nLockTime = 0;  // this concrete value doesn't matter as long as
        // nLockTime <= blockcount
        CFeeRate fixedRate(10000);  // FIXME using a static 10000 Satoshi / KB

        // newDeposits is generated
        vector<DepositParams> newDeposits;
        std::pair<CTransaction, CTransaction> tx_pair = generate_settlement_tx_bitcoin_or_litecoin(
                newDeposits,
                exch,
                feePayment,
                currentDeposits,
                balance_delta,
                100,  // increase the time lock with 100 blocks
                nLockTime,
                fixedRate);

        for (const auto &nd : newDeposits) {
            LL_LOG(
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
            LL_NOTICE("settlement tx (raw) with %d bytes: %s", HexStr(ss).length() / 2, HexStr(ss).c_str());
        }

        {
            // dump the hex
            CDataStream ss(SER_NETWORK, PROTOCOL_VERSION);
            ss << tx_pair.second;

            LL_NOTICE("cancellation tx: %s", tx_pair.second.ToString().c_str());
            LL_NOTICE("cancellation tx (raw) with %d bytes: %s", HexStr(ss).length() / 2, HexStr(ss).c_str());
        }

    return tx_pair;
}

bool test_settle_all()
{
  SelectParams(CBaseChainParams::TESTNET);
  ECC_Start();

  bool ret = true;
  try {
    CBitcoinSecret exch_secret(seckey_from_str("exch"));

    // simulate the exchange
    Exchange exch(exch_secret.GetKey());
    const auto &exch_pubkey = exch.pubKey();
    LL_NOTICE(
        "sgx public key: %s",
        HexStr(exch.pubKey().begin(), exch.pubKey().end()).c_str());
    LL_NOTICE("fee address: %s", exch.P2PKHAddress().ToString().c_str());

    uint32_t depositTimeLock = 1000000;
    vector<DepositParams> params;
    for (auto name : {"alice", "bob", "carol", "david"}) {
      CBitcoinSecret secret(seckey_from_str(name));
      params.emplace_back(
          name, secret.GetKey().GetPubKey(), exch_pubkey, depositTimeLock);

      auto u = params.back();
      LL_NOTICE("%s", u.ToString().c_str());
    }

    // deposit address are:
    // fee: muEPF2wfm1QdLy3LKocBQiW8g73WpzFq72
    // users: alice, bob, ..., david:
    //  2NAqCFC8FazvtUzGv23reB9kQyR9JBW48PB
    //  2NEPd7jWr4mFw2iGeVQvzn5YMZrwL7R7esH
    //  2MvdHzi7sxRbJTwjcH7wMT7z5GDpiq7ktfJ
    //  2MuAaNqaBaWTKFPq5CENWmhd58u7zJQLpnG

/*    
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
*/
  }

  CATCHALL_AND(ret = false)

  ECC_Stop();
  return ret;
}
