#ifndef TESSERACT_SETTLE_H
#define TESSERACT_SETTLE_H

#include "bitcoin/script/script.h"
#include "bitcoin/base58.h"
#include "bitcoin_helpers.h"

enum Action {
  Settlement,
  Withdrawal,
};

class DepositParams {
 private:
  CPubKey userPubkey;
  CPubKey exchPubkey;
  uint32_t locktime;

 public:
  DepositParams(CPubKey userPubkey, CPubKey exchPubkey, uint32_t locktime) :
      userPubkey(userPubkey.begin(), userPubkey.end()),
      exchPubkey(exchPubkey.begin(), exchPubkey.end()),
      locktime(locktime) {}

  CBitcoinAddress address() const;
  CScript deposit_redeemScript() const;
  CScript spend_redeemScript(Action, const CKey &, const CMutableTransaction &, uint32_t nIn) const;
};

class Deposit {
 private:
  DepositParams params;
  CTransaction txin;
  uint32_t nOut;
 public:
  Deposit(DepositParams params, CTransaction txid, uint32_t nOut)
      : params(params), txin(std::move(txid)), nOut(nOut) {};

  const CTxOut& PrevOut() const {
    return txin.vout[nOut];
  }

  const DepositParams &Params() const {
    return params;
  }

  const uint256 &Txid() const {
    return txin.GetHash();
  }

  uint32_t NOut() const {
    return nOut;
  }

  bool Validate() const {
    return IsValidRedeemScript(params.deposit_redeemScript(), PrevOut().scriptPubKey);
  }
};

#endif //TESSERACT_SETTLE_H
