//
// Created by fanz on 9/21/17.
//

#ifndef PROJECT_STATE_H
#define PROJECT_STATE_H

#include "blockfifo.hpp"
#include "balancebook.hpp"
#include "tls_server_threaded.h"

#include "../common/merkle_data.h"

// this file is meant to be used to
// collect the states maintained by a enclave
// and provide interfaces to read / write them.

namespace exch {
namespace enclave {
namespace state {
extern BalanceBook balanceBook;
extern BlockFIFO<1000> blockFIFO;
extern TLSConnectionHandler* connectionHandler;
}
}
}

#ifdef __cplusplus
extern "C" {
#endif

int merkle_proof_verify(const merkle_proof_t *proof);
int ecall_deposit(const merkle_proof_t* merkle_proof, const char* block_hash_hex, const char* public_key_pem);

int ecall_append_block_to_fifo(const char *blockHeaderHex);
int ecall_get_latest_block_hash(unsigned char* o_buf, size_t cap_obuf);

int ssl_conn_init(void);
void ssl_conn_handle(long int thread_id, thread_info_t* thread_info);
void ssl_conn_teardown(void);

#ifdef __cplusplus
}
#endif

#endif //PROJECT_STATE_H
