#ifndef ENCLAVE_T_H__
#define ENCLAVE_T_H__

#include <stdint.h>
#include <wchar.h>
#include <stddef.h>
#include "sgx_edger8r.h" /* for sgx_ocall etc. */

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


int ssl_conn_init();
void ssl_conn_teardown();
void ssl_conn_handle(long int thread_id, thread_info_t* thread_info);
int ecall_append_block_to_fifo(const char* blockHeaderHex);
int test_tls_client(const char* hostname, unsigned int port);
int enclaveTest();
int rsa_keygen_in_seal(const char* subject_name, unsigned char* o_sealed, size_t cap_sealed, unsigned char* o_pubkey, size_t cap_pubkey, unsigned char* o_csr, size_t cap_csr);
int unseal_secret_and_leak_public_key(const sgx_sealed_data_t* secret, size_t secret_len, unsigned char* pubkey, size_t cap_pubkey);
int provision_rsa_id(const unsigned char* sealed_rsa_secret_key, size_t secret_len, const char* cert_pem);
int query_rsa_pubkey(unsigned char* pubkey, size_t cap_pubkey, char* cert_pem, size_t cap_cert_pem);
int merkle_proof_verify(const char* root, const merkle_proof_t* proof);
void dummy();

sgx_status_t SGX_CDECL ocall_mbedtls_net_connect(int* retval, mbedtls_net_context* ctx, const char* host, const char* port, int proto);
sgx_status_t SGX_CDECL ocall_mbedtls_net_bind(int* retval, mbedtls_net_context* ctx, const char* bind_ip, const char* port, int proto);
sgx_status_t SGX_CDECL ocall_mbedtls_net_accept(int* retval, mbedtls_net_context* bind_ctx, mbedtls_net_context* client_ctx, void* client_ip, size_t buf_size, size_t* ip_len);
sgx_status_t SGX_CDECL ocall_mbedtls_net_set_block(int* retval, mbedtls_net_context* ctx);
sgx_status_t SGX_CDECL ocall_mbedtls_net_set_nonblock(int* retval, mbedtls_net_context* ctx);
sgx_status_t SGX_CDECL ocall_mbedtls_net_usleep(unsigned long int usec);
sgx_status_t SGX_CDECL ocall_mbedtls_net_recv(int* retval, mbedtls_net_context* ctx, unsigned char* buf, size_t len);
sgx_status_t SGX_CDECL ocall_mbedtls_net_send(int* retval, mbedtls_net_context* ctx, const unsigned char* buf, size_t len);
sgx_status_t SGX_CDECL ocall_mbedtls_net_recv_timeout(int* retval, mbedtls_net_context* ctx, unsigned char* buf, size_t len, uint32_t timeout);
sgx_status_t SGX_CDECL ocall_mbedtls_net_free(mbedtls_net_context* ctx);
sgx_status_t SGX_CDECL ocall_print_string(int* retval, const char* str);
sgx_status_t SGX_CDECL sgx_oc_cpuidex(int cpuinfo[4], int leaf, int subleaf);
sgx_status_t SGX_CDECL sgx_thread_wait_untrusted_event_ocall(int* retval, const void* self);
sgx_status_t SGX_CDECL sgx_thread_set_untrusted_event_ocall(int* retval, const void* waiter);
sgx_status_t SGX_CDECL sgx_thread_setwait_untrusted_events_ocall(int* retval, const void* waiter, const void* self);
sgx_status_t SGX_CDECL sgx_thread_set_multiple_untrusted_events_ocall(int* retval, const void** waiters, size_t total);
sgx_status_t SGX_CDECL ocall_print_to_std(int* retval, const char* str);
sgx_status_t SGX_CDECL ocall_print_to_err(int* retval, const char* str);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif
