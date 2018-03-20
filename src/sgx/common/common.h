#ifndef EXCH_COMMON_DATA_STRUCT_H
#define EXCH_COMMON_DATA_STRUCT_H

#define NACL_PUBLICKEY_SIZE 32
#define NACL_SECRETKEY_SIZE 32

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

typedef struct {
  const char* fairness;
} init_param;

#endif
