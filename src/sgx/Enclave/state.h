#ifndef PROJECT_STATE_H
#define PROJECT_STATE_H

#include "blockfifo.hpp"
#include "balancebook.hpp"
#include "tls_server_threaded.h"
#include "tls_client.h"

#include "../common/merkle_data.h"
#include "../common/common.h"

// this file is meant to be used to
// collect the states maintained by a enclave
// and provide interfaces to read / write them.

namespace exch {
namespace enclave {
namespace state {
extern BalanceBook balanceBook;
extern BlockFIFO<1000> blockFIFO;
extern TLSConnectionHandler* connectionHandler;
extern TLSClient* tlsClient;
}
}
}

#ifdef __cplusplus
extern "C" {
#endif

int merkle_proof_verify(const merkle_proof_t *proof);
int ecall_bitcoin_deposit(const bitcoin_deposit_t *deposit);

int ecall_append_block_to_fifo(const char *blockHeaderHex);
int ecall_get_latest_block_hash(unsigned char* o_buf, size_t cap_obuf);

int ssl_conn_init(void);
void ssl_conn_handle(long int thread_id, thread_info_t* thread_info);
void ssl_conn_teardown(void);

int ssl_client_init(const char* hostname, unsigned int port);
int ssl_client_write_test(void);
void ssl_client_teardown(void);

#ifdef __cplusplus
}
#endif

#endif //PROJECT_STATE_H
