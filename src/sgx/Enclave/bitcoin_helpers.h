#ifndef TESSERACT_BITCOIN_HELPERS_H
#define TESSERACT_BITCOIN_HELPERS_H

#include "bitcoin/script/script.h"
#include "bitcoin/base58.h"
#include "bitcoin/key.h"
#include <vector>
#include <bitcoin/primitives/transaction.h>

std::string ScriptToAsmStr(const CScript &script);
CScript generate_simple_cltv_script(const CPubKey& pubkey, uint32_t lockTime);
CScript generate_deposit_script(const CPubKey& userPubkey, const CPubKey& exchPubkey, uint32_t lockTime);
CBitcoinAddress create_p2sh_address(const CScript& script);
bool IsValidRedeemScript(const CScript &redeemScript, const CScript &scriptPubKey);

class OutPoint {
 private:
  CTransactionRef tx;
  uint32_t nOut;
 public:
  OutPoint(CTransaction &tx, uint32_t nOut) : tx(MakeTransactionRef(tx)), nOut(nOut) {}
  const CTxOut &GetTxOut() const { return tx.get()->vout.at(nOut); }
  const uint256 &GetTxHash() const { return tx.get()->GetHash(); }
  uint32_t GetNOut() const { return nOut; }
  const COutPoint ToCOutPoint() const { return COutPoint(GetTxHash(), nOut); }
};



#endif //TESSERACT_BITCOIN_HELPERS_H
