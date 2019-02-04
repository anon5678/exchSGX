#ifndef TESSERACT_BITCOIN_HELPERS_H
#define TESSERACT_BITCOIN_HELPERS_H

#include <bitcoin/primitives/transaction.h>
#include <vector>
#include "bitcoin/base58.h"
#include "bitcoin/key.h"
#include "bitcoin/script/script.h"

std::string ScriptToAsmStr(const CScript &script);
CScript generate_simple_cltv_script(const CPubKey &pubkey, uint32_t lockTime);
CScript generate_deposit_script(
    const CPubKey &userPubkey, const CPubKey &exchPubkey, uint32_t lockTime);
CBitcoinAddress create_p2sh_address(const CScript &script);
bool validate_redeemScript(
    const CScript &redeemScript, const CScript &scriptPubKey);
bool DecodeHexTx(
    CMutableTransaction &tx, const std::string &strHexTx, bool fTryNoWitness);

// used for testing
CKey seckey_from_str(const std::string &str);

class OutPoint
{
 private:
  CTransactionRef tx;
  uint32_t nOut;

 public:
  OutPoint(CTransaction &tx, uint32_t nOut)
      : tx(MakeTransactionRef(tx)), nOut(nOut)
  {
  }
  const CTxOut &GetTxOut() const { return tx.get()->vout.at(nOut); }
  const uint256 &GetTxHash() const { return tx.get()->GetHash(); }
  uint32_t GetNOut() const { return nOut; }
  const COutPoint ToCOutPoint() const { return COutPoint(GetTxHash(), nOut); }
};

#include <stdio.h>

#define MUST_TRUE(c)                  \
  do {                                \
    if (!(c)) {                       \
      char buf[BUFSIZ] = {'\0'};      \
      snprintf(                       \
          buf,                        \
          sizeof buf,                 \
          "assert failed at %s:%d",   \
          strrchr(__FILE__, '/') + 1, \
          __LINE__);                  \
      throw std::runtime_error(buf);  \
    }                                 \
  } while (false)

#define MUST_TRUE_OR(c, msg)          \
  do {                                \
    if (!(c)) {                       \
      char buf[BUFSIZ] = {'\0'};      \
      snprintf(                       \
          buf,                        \
          sizeof buf,                 \
          "[%s:%d] %s",               \
          strrchr(__FILE__, '/') + 1, \
          __LINE__,                   \
          msg);                       \
      throw std::runtime_error(buf);  \
    }                                 \
  } while (false)

#endif  // TESSERACT_BITCOIN_HELPERS_H
