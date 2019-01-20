#include "settle.h"
#include "bitcoin_helpers.h"
#include "bitcoin/utilstrencodings.h"
#include "bitcoin/streams.h"

using std::vector;

CBitcoinAddress DepositParams::address() const {
  return create_p2sh_address(this->deposit_redeemScript());
}

CScript DepositParams::deposit_redeemScript() const {
  return CScript() << OP_IF << ToByteVector(exchPubkey) << OP_CHECKSIG << OP_ELSE << locktime
                   << OP_CHECKLOCKTIMEVERIFY << OP_DROP << ToByteVector(userPubkey) << OP_CHECKSIG << OP_ENDIF;
}

CScript DepositParams::spend_redeemScript(Action action,
                                          const CKey &privKey,
                                          const CMutableTransaction &unsignedTx,
                                          uint32_t nIn) const {
  CScript branch;
  switch (action) {
    //! when user withdraws the ELSE branch is taken
    case Action::Withdrawal:branch << OP_FALSE;
      break;
    case Action::Settlement:branch << OP_TRUE;
  }

  // note: amount is set to zero since it's not used in SIGVERSION_BASE anyway.
  auto sighash = SignatureHash(deposit_redeemScript(), unsignedTx, nIn, SIGHASH_ALL, 0, SIGVERSION_BASE);

  std::vector<unsigned char> vchSig;
  privKey.Sign(sighash, vchSig);

  auto globalHandle = std::unique_ptr<ECCVerifyHandle>(new ECCVerifyHandle());
  if (!privKey.GetPubKey().Verify(sighash, vchSig)) {
    throw std::runtime_error("Sign() generated an invalid signature");
  }

  // push the SIGHASH_ALL byte.
  vchSig.push_back((unsigned char) SIGHASH_ALL);

  auto s = (CScript() << ToByteVector(vchSig)) + (branch << ToByteVector(deposit_redeemScript()));
  return s;
}

CTransaction settle_to_single_addr(const CKey &exch_seckey,
                                   const vector<Deposit> &deposits,
                                   const CBitcoinAddress &addr,
                                   uint32_t nlocktime) noexcept(false) {
  CMutableTransaction unsigned_tx;

  CAmount sum_in = 0;

  // populate all of the inputs
  for (const auto &dep: deposits) {
    if (!dep.Validate()) {
      throw std::runtime_error("invalid_script");
    }
    sum_in += dep.PrevOut().nValue;
    // set nSequence=0 to enable CLTV
    unsigned_tx.vin.emplace_back(COutPoint(dep.Txid(), dep.NOut()), CScript(), 0);
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
    auto sigScript = deposits[i].Params().spend_redeemScript(Settlement, exch_seckey, unsigned_tx, i);
    unsigned_tx.vin[i].scriptSig = sigScript;
  }

  auto t = CTransaction(unsigned_tx);

  // verify the script
  auto globalHandle = std::unique_ptr<ECCVerifyHandle>(new ECCVerifyHandle());
  ScriptError serror = SCRIPT_ERR_OK;
  for (uint32_t i = 0; i < deposits.size(); i++) {
    if (!VerifyScript(t.vin[i].scriptSig,
                      deposits[i].PrevOut().scriptPubKey,
                      nullptr,
                      STANDARD_SCRIPT_VERIFY_FLAGS,
                      TransactionSignatureChecker(&t, i, 0),
                      &serror)) {
      throw std::runtime_error("Signing failed: " + std::string(ScriptErrorString(serror)));
    } else {
      LL_NOTICE("success.");
    }
  }

  return t;
}

void test_settlement() {
  try {
    SelectParams(CBaseChainParams::REGTEST);
    ECC_Start();

    CBitcoinSecret exch_secret(seckey_from_str("exch"));

    vector<CBitcoinSecret> users;
    users.emplace_back(seckey_from_str("alice"));
    users.emplace_back(seckey_from_str("bob"));

    const auto &exch_pubKey = exch_secret.GetKey().GetPubKey();

    uint32_t nlocktime = 1000000;  // 1 million block
    vector<DepositParams> params;
    for (const auto &user: users) {
      params.emplace_back(user.GetKey().GetPubKey(), exch_pubKey, nlocktime);
    }

    for (const auto &p: params) {
      LL_NOTICE("please deposit at: %s", p.address().ToString().c_str());
    }

    auto _deposit_tx_hex =
        "0200000000010118d406e01696e50dea833a0fe2ccf6f4b85d1cd673618d3ba4bab6324511772000000000171600141ce7828c2699cc0687cd96eed5d48f586dc895c3fdffffff0300ca9a3b0000000017a914888b3770cf8b1d70e07e39e8612065d05d67a9c48700ca9a3b0000000017a9148157a57e8cabbdf9c54bc48171f12c27d00cb37a8728c2ae2f0000000017a9147a65bac26a3dd505b58c0a41969487915e28d699870247304402204691e31f9d437bf38de2b8950a997dfc5118f15e587f757790099a84b9daaf0e022058bc6995480134d521b5a5f3eb3e250fb9e5e838664129ee2312c32a5611ed8f0121028c07747a9675bddc899a892690acce80eb1aa376548dc9af3c16941083cfc84c8a000000";

    CMutableTransaction _deposit;
    DecodeHexTx(_deposit, _deposit_tx_hex, false);
    CTransaction deposit_tx(_deposit);

    Deposit alice_deposit(params[0], deposit_tx, 0);
    Deposit bob_deposit(params[1], deposit_tx, 1);

    CBitcoinAddress target("2NCoX4m42XUEypfdaWo8m58s1hiMu55gbVv");

    vector<Deposit> deposits;
    deposits.push_back(alice_deposit);
    deposits.push_back(bob_deposit);

    // 148 is the latest block number so that this tx can be included right away
    auto t = settle_to_single_addr(exch_secret.GetKey(), deposits, target, 148);

    // dump the hex
    CDataStream ssTx(SER_NETWORK, PROTOCOL_VERSION);
    ssTx << t;

    LL_NOTICE("Final raw tx: %s", HexStr(ssTx).c_str());
    LL_NOTICE("Interpreted as: %s", t.ToString().c_str());

    ECC_Stop();
  }
  CATCH_STD_AND_ALL_NO_RET
}