#ifndef PROJECT_MERKLE_H
#define PROJECT_MERKLE_H

#include <stdlib.h>

#define BITCOIN_HASH_LENGTH 32

typedef unsigned char bitcoin_hash_t[BITCOIN_HASH_LENGTH];

typedef struct {
  bitcoin_hash_t tx;
  bitcoin_hash_t block_hash;

  int dirvec;

  size_t merkle_branch_len;
  bitcoin_hash_t* merkle_branch[];
} merkle_proof_t;

#endif //PROJECT_MERKLE_H
