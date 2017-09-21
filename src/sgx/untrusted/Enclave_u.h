#ifndef ENCLAVE_U_H__
#define ENCLAVE_U_H__

#include <stdint.h>
#include <wchar.h>
#include <stddef.h>
#include <string.h>
#include "sgx_edger8r.h" /* for sgx_satus_t etc. */

#include "../common/ssl_context.h"
#include "../common/merkle_data.h"
#include "sgx_tseal.h"
#include "mbedtls/net_v.h"
#include "mbedtls/timing_v.h"

#include <stdlib.h> /* for size_t */

#define SGX_CAST(type, item) ((type)(item))

#ifdef __cplusplus
extern "C" {
#endif

int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_mbedtls_net_connect, (mbedtls_net_context* ctx, const char* host, const char* port, int proto));
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_mbedtls_net_bind, (mbedtls_net_context* ctx, const char* bind_ip, const char* port, int proto));
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_mbedtls_net_accept, (mbedtls_net_context* bind_ctx, mbedtls_net_context* client_ctx, void* client_ip, size_t buf_size, size_t* ip_len));
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_mbedtls_net_set_block, (mbedtls_net_context* ctx));
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_mbedtls_net_set_nonblock, (mbedtls_net_context* ctx));
void SGX_UBRIDGE(SGX_NOCONVENTION, ocall_mbedtls_net_usleep, (unsigned long int usec));
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_mbedtls_net_recv, (mbedtls_net_context* ctx, unsigned char* buf, size_t len));
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_mbedtls_net_send, (mbedtls_net_context* ctx, const unsigned char* buf, size_t len));
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_mbedtls_net_recv_timeout, (mbedtls_net_context* ctx, unsigned char* buf, size_t len, uint32_t timeout));
void SGX_UBRIDGE(SGX_NOCONVENTION, ocall_mbedtls_net_free, (mbedtls_net_context* ctx));
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_print_string, (const char* str));
void SGX_UBRIDGE(SGX_CDECL, sgx_oc_cpuidex, (int cpuinfo[4], int leaf, int subleaf));
int SGX_UBRIDGE(SGX_CDECL, sgx_thread_wait_untrusted_event_ocall, (const void* self));
int SGX_UBRIDGE(SGX_CDECL, sgx_thread_set_untrusted_event_ocall, (const void* waiter));
int SGX_UBRIDGE(SGX_CDECL, sgx_thread_setwait_untrusted_events_ocall, (const void* waiter, const void* self));
int SGX_UBRIDGE(SGX_CDECL, sgx_thread_set_multiple_untrusted_events_ocall, (const void** waiters, size_t total));
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_print_to_std, (const char* str));
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_print_to_err, (const char* str));

sgx_status_t ssl_conn_init(sgx_enclave_id_t eid, int* retval);
sgx_status_t ssl_conn_teardown(sgx_enclave_id_t eid);
sgx_status_t ssl_conn_handle(sgx_enclave_id_t eid, long int thread_id, thread_info_t* thread_info);
sgx_status_t ecall_append_block_to_fifo(sgx_enclave_id_t eid, int* retval, const char* blockHeaderHex);
sgx_status_t test_tls_client(sgx_enclave_id_t eid, int* retval, const char* hostname, unsigned int port);
sgx_status_t enclaveTest(sgx_enclave_id_t eid, int* retval);
sgx_status_t rsa_keygen_in_seal(sgx_enclave_id_t eid, int* retval, const char* subject_name, unsigned char* o_sealed, size_t cap_sealed, unsigned char* o_pubkey, size_t cap_pubkey, unsigned char* o_csr, size_t cap_csr);
sgx_status_t unseal_secret_and_leak_public_key(sgx_enclave_id_t eid, int* retval, const sgx_sealed_data_t* secret, size_t secret_len, unsigned char* pubkey, size_t cap_pubkey);
sgx_status_t provision_rsa_id(sgx_enclave_id_t eid, int* retval, const unsigned char* sealed_rsa_secret_key, size_t secret_len, const char* cert_pem);
sgx_status_t query_rsa_pubkey(sgx_enclave_id_t eid, int* retval, unsigned char* pubkey, size_t cap_pubkey, char* cert_pem, size_t cap_cert_pem);
sgx_status_t merkle_proof_verify(sgx_enclave_id_t eid, int* retval, const merkle_proof_t* proof);
sgx_status_t dummy(sgx_enclave_id_t eid);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif
