#include "bitcoin_helpers.h"
#include "bitcoin/streams.h"
#include "bitcoin/utilstrencodings.h"
#include "log.h"

#include <algorithm>
#include "lest/lest.hpp"

using std::vector;

std::string ScriptToAsmStr(const CScript &script)
{
  std::string str;
  opcodetype opcode;
  std::vector<unsigned char> vch;
  CScript::const_iterator pc = script.begin();
  while (pc < script.end()) {
    if (!str.empty()) {
      str += " ";
    }
    if (!script.GetOp(pc, opcode, vch)) {
      str += "[error]";
      return str;
    }
    if (0 <= opcode && opcode <= OP_PUSHDATA4) {
      str += HexStr(vch);
    } else {
      str += GetOpName(opcode);
    }
  }
  return str;
}

//! generate script lockTime << OP_CLTV << OP_DROP << [userPubkey] << OP_CHECKSIG
//! \param userPubkey
//! \param lockTime
//! \return script
CScript generate_simple_cltv_script(
    const CPubKey &userPubkey, uint32_t lockTime)
{
  return CScript() << lockTime << OP_CHECKLOCKTIMEVERIFY << OP_DROP
                   << ToByteVector(userPubkey) << OP_CHECKSIG;
}

//! generate script for deposit. Coins can be spent either by userPubkey after a timeout, or by exchPubkey at any time
//! \param userPubkey
//! \param exchPubkey
//! \param lockTime
//! \return script
CScript generate_deposit_script(
    const CPubKey &userPubkey, const CPubKey &exchPubkey, uint32_t lockTime)
{
  return CScript() << OP_IF << ToByteVector(exchPubkey) << OP_CHECKSIGVERIFY
                   << OP_ELSE << lockTime << OP_CHECKLOCKTIMEVERIFY << OP_DROP
                   << ToByteVector(userPubkey) << OP_CHECKSIGVERIFY << OP_ENDIF;
}

//! create a p2sh address from script
//! \param script
//! \return
CBitcoinAddress create_p2sh_address(const CScript &script)
{
  return CBitcoinAddress(CScriptID(script));
}

//! return true if redeemScript is a valid redeem script for scriptPubkey.
//! It first check if scriptPubkey is of the right format: OP_HASH160 <HASH> OP_EQUAL
//! It then checks hash(redeemScript) == HASH
//! \param redeemScript
//! \param scriptPubKey
//! \return true or else
bool validate_redeemScript(
    const CScript &redeemScript, const CScript &scriptPubKey)
{
  auto redeemScriptHash = Hash160(redeemScript.begin(), redeemScript.end());
  std::vector<unsigned char> scriptHash;

  if (!scriptPubKey.IsPayToScriptHash(scriptHash)) {
    LL_CRITICAL("not an P2SH");
    return false;
  } else {
    return equal(
        std::begin(scriptHash),
        std::end(scriptHash),
        std::begin(redeemScriptHash));
  }
}

bool DecodeHexTx(
    CMutableTransaction &tx, const std::string &strHexTx, bool fTryNoWitness)
{
  if (!IsHex(strHexTx)) return false;
  vector<unsigned char> txData(ParseHex(strHexTx));
  if (fTryNoWitness) {
    CDataStream ssData(
        txData,
        SER_NETWORK,
        PROTOCOL_VERSION | SERIALIZE_TRANSACTION_NO_WITNESS);
    try {
      ssData >> tx;
      if (ssData.eof()) {
        return true;
      }
    } catch (const std::exception &) {
      // Fall through.
    }
  }
  CDataStream ssData(txData, SER_NETWORK, PROTOCOL_VERSION);
  try {
    ssData >> tx;
  } catch (const std::exception &) {
    return false;
  }
  return true;
}

CKey seckey_from_str(const std::string &str)
{
  auto bytes = Hash(str.begin(), str.end());
  CKey key;
  key.Set(bytes.begin(), bytes.end(), true);
  return key;
}