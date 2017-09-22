//
// Created by fanz on 9/21/17.
//

#include "state.h"
#include "../common/utils.h"
#include "pprint.h"
#include "log.h"
#include "bitcoin/crypto/sha256.h"
#include "../common/merkle_data.h"

#include <string>

using namespace std;
using namespace exch::enclave;

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

static string __merkle_proof_verify(const merkle_proof_t *proof){
  bitcoin_hash_t curr;

  memcpy(curr, proof->tx, sizeof curr);
  byte_swap(curr, sizeof curr);

  int direction = proof->dirvec;

  for (unsigned int i = 0; direction > 1 && i < proof->merkle_branch_len; ++i, direction >>= 1) {
    if (proof->merkle_branch[i] == nullptr) {
      sha256double(curr, curr, curr);
      continue;
    }
    if (direction & 1)
      sha256double(curr, *proof->merkle_branch[i], curr);
    else
      sha256double(*proof->merkle_branch[i], curr, curr);
  }

  byte_swap(curr, BITCOIN_HASH_LENGTH);
  return bin2hex(curr, BITCOIN_HASH_LENGTH);
}

int merkle_proof_verify(const merkle_proof_t *proof){
  LL_NOTICE("root: %s", __merkle_proof_verify(proof).c_str());
  return 0;
}

int ecall_deposit(const merkle_proof_t* merkle_proof, const char* block_hash_hex, const char* public_key_pem) {
  uint256 _block_hash;
  _block_hash.SetHex(block_hash_hex);
  const CBlockHeader* h = state::blockFIFO.find_block(_block_hash);
  if (h) {
    LL_LOG("find block %s", h->GetHash().GetHex().c_str());
    string calc_root = __merkle_proof_verify(merkle_proof);
    if (calc_root == h->GetHash().GetHex()) {
      LL_NOTICE("deposit %s accepted", bin2hex(merkle_proof->tx, 32).c_str());
      LL_CRITICAL("balance update has not been implemented");

      int amount = 100;
      state::balanceBook.deposit(public_key_pem, amount);
    }
    else {
      LL_CRITICAL("deposit %s NOT accepted", bin2hex(merkle_proof->tx, 32).c_str());
      LL_CRITICAL("expected root: %s", h->hashMerkleRoot.ToString().c_str());
      LL_CRITICAL("calculated root: %s", calc_root.c_str());
    }
  }
  else {
    LL_CRITICAL("doesn't find any");
    return -1;
  }

  return 0;
}
