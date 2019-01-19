#include "bitcoin_helpers.h"
#include "log.h"
#include <algorithm>
#include "bitcoin/utilstrencodings.h"

std::string ScriptToAsmStr(const CScript& script){
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
      // printf("Length vch: %d\n", vch.size());
    } else {
      str += GetOpName(opcode);
    }
  }
  return str;
}