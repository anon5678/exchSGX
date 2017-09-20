#include <string>
#include "../common/merkle_data.h"
#include "../common/utils.h"
#include "log.h"


using namespace std;

bool verify_merkle_proof(const string& root, const merkle_proof_t* proof){
  bitcoin_hash_t curr;
  bitcoin_hash_t tmp;

  LL_CRITICAL("length is %d", sizeof curr);
  memcpy(curr, proof->tx, sizeof curr);
  byte_swap(curr, sizeof curr);

  int direction = proof->dirvec;

#if 0

  for (int i = 0; direction > 1; ++i, direction >>= 1) {
    if ((branch[i]).empty()) {
      sha256double(curr.data(), curr.data(), curr.data());
      continue;
    }
    //std::memcpy(tmp, (base64_decode(branch[i])).data(), 32);
    hex2bin(tmp.data(), branch[i].c_str());
    if (direction & 1)
      sha256double(curr.data(), tmp.data(), curr.data());
    else
      sha256double(tmp.data(), curr.data(), curr.data());
  }

  cout << "verify: ";
  byte_swap(curr.data(), 32);
  hexdump(curr.data(), 32);
#endif
}
