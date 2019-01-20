#include "settle.h"
#include "bitcoin_helpers.h"

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

  std::vector<unsigned char> vchSig;

  // note: amount is set to zero since it's not used in SIGVERSION_BASE anyway.
  auto sighash = SignatureHash(deposit_redeemScript(), unsignedTx, nIn, SIGHASH_ALL, 0, SIGVERSION_BASE);
  privKey.Sign(sighash, vchSig);

  auto globalHandle = std::unique_ptr<ECCVerifyHandle>(new ECCVerifyHandle());
  if (!privKey.GetPubKey().Verify(sighash, vchSig)) {
    throw std::runtime_error("Sign() generated an invalid signature");
  }

  // push the SIGHASH_ALL byte.
  vchSig.push_back((unsigned char) SIGHASH_ALL);

  return CScript() << ToByteVector(vchSig) << branch << ToByteVector(deposit_redeemScript());
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

  auto tx_size = 4 + 2 + deposits.size() * 153 + 1 + 34 + 4;
  // FIXME: use estimatesmartfee instead
  CFeeRate fixed_rate(10000);
  CAmount fees = fixed_rate.GetFee(tx_size);
  LL_NOTICE("fees = %d", fees);

  CAmount amount = sum_in - fees;

  // populate the (only) output
  unsigned_tx.vout.emplace_back(amount, GetScriptForDestination(addr.Get()));
  unsigned_tx.nLockTime = nlocktime;

  // sign all the inputs
  for (uint32_t i = 0; i < deposits.size(); i++) {
    auto sigScript = deposits[i].Params().spend_redeemScript(Settlement, exch_seckey, unsigned_tx, i);
    unsigned_tx.vin[i].scriptSig = sigScript;
  }

  return CTransaction(unsigned_tx);
}