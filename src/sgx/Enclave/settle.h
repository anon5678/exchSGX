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
  DepositParams() = delete;
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
  DepositParams _params;
  CTransaction _txin;
  uint32_t _nOut;

 public:
  Deposit(DepositParams params, CTransaction txin, uint32_t nOut)
      : _params(std::move(params)), _txin(std::move(txin)), _nOut(nOut){};

  const CTxOut &prevOut() const { return _txin.vout[_nOut]; }

  const DepositParams &params() const { return _params; }

  const uint256 &txid() const { return _txin.GetHash(); }

  uint32_t nOut() const { return _nOut; }

  bool Validate() const
  {
    return validate_redeemScript(
        _params.deposit_redeemScript(), prevOut().scriptPubKey);
  }
};

#include "bitcoin/keystore.h"
#include "bitcoin/script/sign.h"

class Exchange
{
 private:
  CKey _privKey;
  CPubKey _pubKey;
  CBitcoinAddress address;
  CScript _scriptPubkey;

 public:
  explicit Exchange(const CKey &privKey) : _privKey(privKey)
  {
    address.Set(privKey.GetPubKey().GetID());

    auto pub = _privKey.GetPubKey();
    _scriptPubkey = GetScriptForDestination(pub.GetID());
    _pubKey.Set(pub.begin(), pub.end());
  }
  const CKey &privKey() const { return _privKey; }
  const CPubKey &pubKey() const { return _pubKey; }
  const CBitcoinAddress &P2PKHAddress() const { return address; }
  const CScript scriptPubkey() const { return _scriptPubkey; }
};

class FeePayment
{
 private:
  CTransaction txin;
  uint32_t _nOut;

 public:
  FeePayment(CTransaction txin, uint32_t nOut)
      : txin(std::move(txin)), _nOut(nOut)
  {
  }

  const CTxOut &prevOut() const { return txin.vout[_nOut]; }

  const uint256 &txid() const { return txin.GetHash(); }

  uint32_t nOut() const { return _nOut; }

  COutPoint ToOutPoint() const { return {txid(), nOut()}; }

  bool Sign(
      const CKey &exch_key,
      CMutableTransaction &unsigned_tx,
      unsigned long nIn) const
  {
    CBasicKeyStore tmp;
    tmp.AddKey(exch_key);
    return SignSignature(tmp, txin, unsigned_tx, nIn, SIGHASH_ALL);
  }
};

#endif  // TESSERACT_SETTLE_H
