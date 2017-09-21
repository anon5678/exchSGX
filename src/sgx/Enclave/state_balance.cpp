//
// Created by fanz on 9/21/17.
//

#include "state.h"
#include "../common/utils.h"
#include "pprint.h"
#include "log.h"
#include "bitcoin/crypto/sha256.h"

#include <string>

using namespace std;

// s1+s2 are the 32+32 bytes input, dst is 32 bytes output
// dst = hash(hash(s1 || s2))
static void sha256double(
    const unsigned char* s1,
    const unsigned char* s2,
    unsigned char* dst) {
  CSHA256 h1, h2;
  unsigned char tmp[BITCOIN_HASH_LENGTH];

  h1.Write(s1, BITCOIN_HASH_LENGTH);
  h1.Write(s2, BITCOIN_HASH_LENGTH);
  h1.Finalize(tmp);

  h2.Write(tmp, sizeof tmp);
  h2.Finalize(dst);
}

int merkle_proof_verify(const merkle_proof_t *proof){
  bitcoin_hash_t curr;

  memcpy(curr, proof->tx, sizeof curr);
  byte_swap(curr, sizeof curr);

  int direction = proof->dirvec;

  for (int i = 0; direction > 1 && i < proof->merkle_branch_len; ++i, direction >>= 1) {
    if (proof->merkle_branch[i] == nullptr) {
      sha256double(curr, curr, curr);
      continue;
    }
    if (direction & 1)
      sha256double(curr, *proof->merkle_branch[i], curr);
    else
      sha256double(*proof->merkle_branch[i], curr, curr);
  }

  byte_swap(curr, 32);
  printf_sgx("root: %s\n", bin2hex(curr, 32).c_str());

  return 0;
}

int ecall_deposit(const merkle_proof_t* merkle_proof, const bitcoin_hash_t* block, const char* public_key_pem) {

}
