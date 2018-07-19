#include <stdlib.h>
#include "../common/merkle_data.h"
#include "../common/utils.h"
#include <stdio.h>

// this code is for untrusted part only
// make sure IN_ENCLAVE is not set

merkle_proof_t *merkle_proof_init(size_t n) {
  auto o = (merkle_proof_t *) malloc(sizeof(merkle_proof_t) + n * sizeof(bitcoin_hash_t *));

  o->tx_raw_hex = nullptr;
  o->dirvec = 0;
  o->merkle_branch_len = n;

  for (int i = 0; i < n; i++) {
    o->merkle_branch[i] = nullptr;
  }

  return o;
}

void merkle_proof_dump(const merkle_proof_t *p) {
  printf("tx: %s\n", bin2hex(p->tx, sizeof p->tx).c_str());
  printf("tx_raw: %s\n", p->tx_raw_hex);
  printf("direction: %d\n", p->dirvec);
  for (int i = 0; i < p->merkle_branch_len; i++) {
    if (p->merkle_branch[i] == nullptr) {
      printf("branch %d: NULL\n", i);
    } else {
      printf("branch %d: %s\n", i, bin2hex((unsigned char *) p->merkle_branch[i], BITCOIN_HASH_LENGTH).c_str());
    }
  }
}

void merkle_proof_free(merkle_proof_t *p) {
  for (int i = 0; i < p->merkle_branch_len; i++) {
    if (p->merkle_branch[i]) {
      free(p->merkle_branch[i]);
    }
  }
  free(p);
}
