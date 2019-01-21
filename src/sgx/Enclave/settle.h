#ifndef TESSERACT_SETTLE_H
#define TESSERACT_SETTLE_H

#include "bitcoin/base58.h"
#include "bitcoin/script/script.h"
#include "bitcoin_helpers.h"

bool test_settlement();
bool test_settle_all();

enum Action {
  Settlement,
  Withdrawal,
};

class DepositParams
{
 private:
  CPubKey userPubkey;
  CPubKey exchPubkey;
  uint32_t locktime;

  CBitcoinAddress _depositAddress;
  CScript _scriptPubkey;
  CScript _redeemScript;
  CScriptID _redeemScriptId;

  void _gen_deposit_redeemScript();

 public:
  DepositParams(CPubKey userPubkey, CPubKey exchPubkey, uint32_t locktime)
      : userPubkey(userPubkey.begin(), userPubkey.end()),
        exchPubkey(exchPubkey.begin(), exchPubkey.end()),
        locktime(locktime)
  {
    _gen_deposit_redeemScript();

    _redeemScriptId = CScriptID(_redeemScript);
    _depositAddress.Set(_redeemScriptId);
    _scriptPubkey = GetScriptForDestination(_redeemScriptId);
  }

  DepositParams UpdateLockTime(uint32_t lockTimeDelta) const
  {
    return {userPubkey, exchPubkey, locktime + lockTimeDelta};
  }

  const CBitcoinAddress &address() const { return _depositAddress; }
  const CScript &scriptPubkey() const { return _scriptPubkey; }
  const CScript &deposit_redeemScript() const { return _redeemScript; }
  CScript spend_redeemScript(
      Action, const CKey &, const CMutableTransaction &, uint32_t nIn) const;
};

class Deposit
{
 private:
  DepositParams params;
  CTransaction txin;
  uint32_t nOut;

 public:
  Deposit(DepositParams params, CTransaction txin, uint32_t nOut)
      : params(params), txin(std::move(txin)), nOut(nOut){};

  const CTxOut &PrevOut() const { return txin.vout[nOut]; }

  const DepositParams &Params() const { return params; }

  const uint256 &Txid() const { return txin.GetHash(); }

  uint32_t NOut() const { return nOut; }

  bool Validate() const
  {
    return validate_redeemScript(
        params.deposit_redeemScript(), PrevOut().scriptPubKey);
  }
};

#include "bitcoin/keystore.h"
#include "bitcoin/script/sign.h"

class FeePayment
{
 private:
  CTransactionRef txin;
  uint32_t _nOut;

 public:
  FeePayment(const CTransaction &txin, uint32_t nOut)
      : txin(MakeTransactionRef(txin)), _nOut(nOut)
  {
  }

  const CTxOut &prevOut() const { return txin.get()->vout[_nOut]; }

  const uint256 &txid() const { return txin.get()->GetHash(); }

  uint32_t nOut() const { return _nOut; }

  COutPoint ToOutPoint() const { return {txid(), nOut()}; }

  bool Sign(
      const CKey &exch_key,
      CMutableTransaction &unsigned_tx,
      unsigned long nIn) const
  {
    CBasicKeyStore tmp;
    tmp.AddKey(exch_key);
    return SignSignature(tmp, *txin.get(), unsigned_tx, nIn, SIGHASH_ALL);
  }
};

#endif  // TESSERACT_SETTLE_H
