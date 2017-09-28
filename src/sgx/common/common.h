#ifndef EXCH_COMMON_DATA_STRUCT_H
#define EXCH_COMMON_DATA_STRUCT_H

#define RSA_SECRET_KEY_SIZE 2048

#include "merkle_data.h"

typedef struct {
  const merkle_proof_t* merkle_proof;
  const char* tx_raw;
  const char* block;
  const char* deposit_recipient_addr;
  const char* deposit_refund_addr;
  unsigned long deposit_timeout;
  const char* pubkey_pem;
} bitcoin_deposit_t;

#endif
