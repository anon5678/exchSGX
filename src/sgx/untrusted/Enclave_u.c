#include "Enclave_u.h"
#include <errno.h>



typedef struct ms_ssl_conn_handle_t {
	long int ms_thread_id;
	thread_info_t* ms_thread_info;
} ms_ssl_conn_handle_t;

typedef struct ms_appendBlockToFIFO_t {
	char* ms_header;
} ms_appendBlockToFIFO_t;

typedef struct ms_test_tls_client_t {
	int ms_retval;
	char* ms_hostname;
	unsigned int ms_port;
} ms_test_tls_client_t;

typedef struct ms_enclaveTest_t {
	int ms_retval;
} ms_enclaveTest_t;

typedef struct ms_keygen_in_seal_t {
	int ms_retval;
	unsigned char* ms_o_sealed;
	size_t* ms_olen;
	unsigned char* ms_o_pubkey;
} ms_keygen_in_seal_t;

typedef struct ms_unseal_secret_and_leak_public_key_t {
	int ms_retval;
	sgx_sealed_data_t* ms_secret;
	size_t ms_secret_len;
	unsigned char* ms_pubkey;
} ms_unseal_secret_and_leak_public_key_t;

typedef struct ms_provision_hybrid_key_t {
	int ms_retval;
	sgx_sealed_data_t* ms_secret;
	size_t ms_secret_len;
} ms_provision_hybrid_key_t;

typedef struct ms_get_hybrid_pubkey_t {
	int ms_retval;
	uint8_t* ms_pubkey;
} ms_get_hybrid_pubkey_t;

typedef struct ms_provision_rsa_id_t {
	unsigned char* ms_encrypted_rsa_id;
	size_t ms_buf_len;
} ms_provision_rsa_id_t;


typedef struct ms_ocall_mbedtls_net_connect_t {
	int ms_retval;
	mbedtls_net_context* ms_ctx;
	char* ms_host;
	char* ms_port;
	int ms_proto;
} ms_ocall_mbedtls_net_connect_t;

typedef struct ms_ocall_mbedtls_net_bind_t {
	int ms_retval;
	mbedtls_net_context* ms_ctx;
	char* ms_bind_ip;
	char* ms_port;
	int ms_proto;
} ms_ocall_mbedtls_net_bind_t;

typedef struct ms_ocall_mbedtls_net_accept_t {
	int ms_retval;
	mbedtls_net_context* ms_bind_ctx;
	mbedtls_net_context* ms_client_ctx;
	void* ms_client_ip;
	size_t ms_buf_size;
	size_t* ms_ip_len;
} ms_ocall_mbedtls_net_accept_t;

typedef struct ms_ocall_mbedtls_net_set_block_t {
	int ms_retval;
	mbedtls_net_context* ms_ctx;
} ms_ocall_mbedtls_net_set_block_t;

typedef struct ms_ocall_mbedtls_net_set_nonblock_t {
	int ms_retval;
	mbedtls_net_context* ms_ctx;
} ms_ocall_mbedtls_net_set_nonblock_t;

typedef struct ms_ocall_mbedtls_net_usleep_t {
	unsigned long int ms_usec;
} ms_ocall_mbedtls_net_usleep_t;

typedef struct ms_ocall_mbedtls_net_recv_t {
	int ms_retval;
	mbedtls_net_context* ms_ctx;
	unsigned char* ms_buf;
	size_t ms_len;
} ms_ocall_mbedtls_net_recv_t;

typedef struct ms_ocall_mbedtls_net_send_t {
	int ms_retval;
	mbedtls_net_context* ms_ctx;
	unsigned char* ms_buf;
	size_t ms_len;
} ms_ocall_mbedtls_net_send_t;

typedef struct ms_ocall_mbedtls_net_recv_timeout_t {
	int ms_retval;
	mbedtls_net_context* ms_ctx;
	unsigned char* ms_buf;
	size_t ms_len;
	uint32_t ms_timeout;
} ms_ocall_mbedtls_net_recv_timeout_t;

typedef struct ms_ocall_mbedtls_net_free_t {
	mbedtls_net_context* ms_ctx;
} ms_ocall_mbedtls_net_free_t;

typedef struct ms_ocall_print_string_t {
	int ms_retval;
	char* ms_str;
} ms_ocall_print_string_t;

typedef struct ms_sgx_oc_cpuidex_t {
	int* ms_cpuinfo;
	int ms_leaf;
	int ms_subleaf;
} ms_sgx_oc_cpuidex_t;

typedef struct ms_sgx_thread_wait_untrusted_event_ocall_t {
	int ms_retval;
	void* ms_self;
} ms_sgx_thread_wait_untrusted_event_ocall_t;

typedef struct ms_sgx_thread_set_untrusted_event_ocall_t {
	int ms_retval;
	void* ms_waiter;
} ms_sgx_thread_set_untrusted_event_ocall_t;

typedef struct ms_sgx_thread_setwait_untrusted_events_ocall_t {
	int ms_retval;
	void* ms_waiter;
	void* ms_self;
} ms_sgx_thread_setwait_untrusted_events_ocall_t;

typedef struct ms_sgx_thread_set_multiple_untrusted_events_ocall_t {
	int ms_retval;
	void** ms_waiters;
	size_t ms_total;
} ms_sgx_thread_set_multiple_untrusted_events_ocall_t;

typedef struct ms_ocall_print_to_std_t {
	int ms_retval;
	char* ms_str;
} ms_ocall_print_to_std_t;

typedef struct ms_ocall_print_to_err_t {
	int ms_retval;
	char* ms_str;
} ms_ocall_print_to_err_t;

static sgx_status_t SGX_CDECL Enclave_ocall_mbedtls_net_connect(void* pms)
{
	ms_ocall_mbedtls_net_connect_t* ms = SGX_CAST(ms_ocall_mbedtls_net_connect_t*, pms);
	ms->ms_retval = ocall_mbedtls_net_connect(ms->ms_ctx, (const char*)ms->ms_host, (const char*)ms->ms_port, ms->ms_proto);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_mbedtls_net_bind(void* pms)
{
	ms_ocall_mbedtls_net_bind_t* ms = SGX_CAST(ms_ocall_mbedtls_net_bind_t*, pms);
	ms->ms_retval = ocall_mbedtls_net_bind(ms->ms_ctx, (const char*)ms->ms_bind_ip, (const char*)ms->ms_port, ms->ms_proto);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_mbedtls_net_accept(void* pms)
{
	ms_ocall_mbedtls_net_accept_t* ms = SGX_CAST(ms_ocall_mbedtls_net_accept_t*, pms);
	ms->ms_retval = ocall_mbedtls_net_accept(ms->ms_bind_ctx, ms->ms_client_ctx, ms->ms_client_ip, ms->ms_buf_size, ms->ms_ip_len);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_mbedtls_net_set_block(void* pms)
{
	ms_ocall_mbedtls_net_set_block_t* ms = SGX_CAST(ms_ocall_mbedtls_net_set_block_t*, pms);
	ms->ms_retval = ocall_mbedtls_net_set_block(ms->ms_ctx);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_mbedtls_net_set_nonblock(void* pms)
{
	ms_ocall_mbedtls_net_set_nonblock_t* ms = SGX_CAST(ms_ocall_mbedtls_net_set_nonblock_t*, pms);
	ms->ms_retval = ocall_mbedtls_net_set_nonblock(ms->ms_ctx);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_mbedtls_net_usleep(void* pms)
{
	ms_ocall_mbedtls_net_usleep_t* ms = SGX_CAST(ms_ocall_mbedtls_net_usleep_t*, pms);
	ocall_mbedtls_net_usleep(ms->ms_usec);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_mbedtls_net_recv(void* pms)
{
	ms_ocall_mbedtls_net_recv_t* ms = SGX_CAST(ms_ocall_mbedtls_net_recv_t*, pms);
	ms->ms_retval = ocall_mbedtls_net_recv(ms->ms_ctx, ms->ms_buf, ms->ms_len);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_mbedtls_net_send(void* pms)
{
	ms_ocall_mbedtls_net_send_t* ms = SGX_CAST(ms_ocall_mbedtls_net_send_t*, pms);
	ms->ms_retval = ocall_mbedtls_net_send(ms->ms_ctx, (const unsigned char*)ms->ms_buf, ms->ms_len);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_mbedtls_net_recv_timeout(void* pms)
{
	ms_ocall_mbedtls_net_recv_timeout_t* ms = SGX_CAST(ms_ocall_mbedtls_net_recv_timeout_t*, pms);
	ms->ms_retval = ocall_mbedtls_net_recv_timeout(ms->ms_ctx, ms->ms_buf, ms->ms_len, ms->ms_timeout);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_mbedtls_net_free(void* pms)
{
	ms_ocall_mbedtls_net_free_t* ms = SGX_CAST(ms_ocall_mbedtls_net_free_t*, pms);
	ocall_mbedtls_net_free(ms->ms_ctx);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_print_string(void* pms)
{
	ms_ocall_print_string_t* ms = SGX_CAST(ms_ocall_print_string_t*, pms);
	ms->ms_retval = ocall_print_string((const char*)ms->ms_str);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_sgx_oc_cpuidex(void* pms)
{
	ms_sgx_oc_cpuidex_t* ms = SGX_CAST(ms_sgx_oc_cpuidex_t*, pms);
	sgx_oc_cpuidex(ms->ms_cpuinfo, ms->ms_leaf, ms->ms_subleaf);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_sgx_thread_wait_untrusted_event_ocall(void* pms)
{
	ms_sgx_thread_wait_untrusted_event_ocall_t* ms = SGX_CAST(ms_sgx_thread_wait_untrusted_event_ocall_t*, pms);
	ms->ms_retval = sgx_thread_wait_untrusted_event_ocall((const void*)ms->ms_self);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_sgx_thread_set_untrusted_event_ocall(void* pms)
{
	ms_sgx_thread_set_untrusted_event_ocall_t* ms = SGX_CAST(ms_sgx_thread_set_untrusted_event_ocall_t*, pms);
	ms->ms_retval = sgx_thread_set_untrusted_event_ocall((const void*)ms->ms_waiter);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_sgx_thread_setwait_untrusted_events_ocall(void* pms)
{
	ms_sgx_thread_setwait_untrusted_events_ocall_t* ms = SGX_CAST(ms_sgx_thread_setwait_untrusted_events_ocall_t*, pms);
	ms->ms_retval = sgx_thread_setwait_untrusted_events_ocall((const void*)ms->ms_waiter, (const void*)ms->ms_self);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_sgx_thread_set_multiple_untrusted_events_ocall(void* pms)
{
	ms_sgx_thread_set_multiple_untrusted_events_ocall_t* ms = SGX_CAST(ms_sgx_thread_set_multiple_untrusted_events_ocall_t*, pms);
	ms->ms_retval = sgx_thread_set_multiple_untrusted_events_ocall((const void**)ms->ms_waiters, ms->ms_total);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_print_to_std(void* pms)
{
	ms_ocall_print_to_std_t* ms = SGX_CAST(ms_ocall_print_to_std_t*, pms);
	ms->ms_retval = ocall_print_to_std((const char*)ms->ms_str);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_print_to_err(void* pms)
{
	ms_ocall_print_to_err_t* ms = SGX_CAST(ms_ocall_print_to_err_t*, pms);
	ms->ms_retval = ocall_print_to_err((const char*)ms->ms_str);

	return SGX_SUCCESS;
}

static const struct {
	size_t nr_ocall;
	void * table[18];
} ocall_table_Enclave = {
	18,
	{
		(void*)Enclave_ocall_mbedtls_net_connect,
		(void*)Enclave_ocall_mbedtls_net_bind,
		(void*)Enclave_ocall_mbedtls_net_accept,
		(void*)Enclave_ocall_mbedtls_net_set_block,
		(void*)Enclave_ocall_mbedtls_net_set_nonblock,
		(void*)Enclave_ocall_mbedtls_net_usleep,
		(void*)Enclave_ocall_mbedtls_net_recv,
		(void*)Enclave_ocall_mbedtls_net_send,
		(void*)Enclave_ocall_mbedtls_net_recv_timeout,
		(void*)Enclave_ocall_mbedtls_net_free,
		(void*)Enclave_ocall_print_string,
		(void*)Enclave_sgx_oc_cpuidex,
		(void*)Enclave_sgx_thread_wait_untrusted_event_ocall,
		(void*)Enclave_sgx_thread_set_untrusted_event_ocall,
		(void*)Enclave_sgx_thread_setwait_untrusted_events_ocall,
		(void*)Enclave_sgx_thread_set_multiple_untrusted_events_ocall,
		(void*)Enclave_ocall_print_to_std,
		(void*)Enclave_ocall_print_to_err,
	}
};
sgx_status_t ssl_conn_init(sgx_enclave_id_t eid)
{
	sgx_status_t status;
	status = sgx_ecall(eid, 0, &ocall_table_Enclave, NULL);
	return status;
}

sgx_status_t ssl_conn_teardown(sgx_enclave_id_t eid)
{
	sgx_status_t status;
	status = sgx_ecall(eid, 1, &ocall_table_Enclave, NULL);
	return status;
}

sgx_status_t ssl_conn_handle(sgx_enclave_id_t eid, long int thread_id, thread_info_t* thread_info)
{
	sgx_status_t status;
	ms_ssl_conn_handle_t ms;
	ms.ms_thread_id = thread_id;
	ms.ms_thread_info = thread_info;
	status = sgx_ecall(eid, 2, &ocall_table_Enclave, &ms);
	return status;
}

sgx_status_t appendBlockToFIFO(sgx_enclave_id_t eid, const char* header)
{
	sgx_status_t status;
	ms_appendBlockToFIFO_t ms;
	ms.ms_header = (char*)header;
	status = sgx_ecall(eid, 3, &ocall_table_Enclave, &ms);
	return status;
}

sgx_status_t test_tls_client(sgx_enclave_id_t eid, int* retval, const char* hostname, unsigned int port)
{
	sgx_status_t status;
	ms_test_tls_client_t ms;
	ms.ms_hostname = (char*)hostname;
	ms.ms_port = port;
	status = sgx_ecall(eid, 4, &ocall_table_Enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t enclaveTest(sgx_enclave_id_t eid, int* retval)
{
	sgx_status_t status;
	ms_enclaveTest_t ms;
	status = sgx_ecall(eid, 5, &ocall_table_Enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t keygen_in_seal(sgx_enclave_id_t eid, int* retval, unsigned char* o_sealed, size_t* olen, unsigned char* o_pubkey)
{
	sgx_status_t status;
	ms_keygen_in_seal_t ms;
	ms.ms_o_sealed = o_sealed;
	ms.ms_olen = olen;
	ms.ms_o_pubkey = o_pubkey;
	status = sgx_ecall(eid, 6, &ocall_table_Enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t unseal_secret_and_leak_public_key(sgx_enclave_id_t eid, int* retval, const sgx_sealed_data_t* secret, size_t secret_len, unsigned char* pubkey)
{
	sgx_status_t status;
	ms_unseal_secret_and_leak_public_key_t ms;
	ms.ms_secret = (sgx_sealed_data_t*)secret;
	ms.ms_secret_len = secret_len;
	ms.ms_pubkey = pubkey;
	status = sgx_ecall(eid, 7, &ocall_table_Enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t provision_hybrid_key(sgx_enclave_id_t eid, int* retval, const sgx_sealed_data_t* secret, size_t secret_len)
{
	sgx_status_t status;
	ms_provision_hybrid_key_t ms;
	ms.ms_secret = (sgx_sealed_data_t*)secret;
	ms.ms_secret_len = secret_len;
	status = sgx_ecall(eid, 8, &ocall_table_Enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t get_hybrid_pubkey(sgx_enclave_id_t eid, int* retval, uint8_t pubkey[65])
{
	sgx_status_t status;
	ms_get_hybrid_pubkey_t ms;
	ms.ms_pubkey = (uint8_t*)pubkey;
	status = sgx_ecall(eid, 9, &ocall_table_Enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t provision_rsa_id(sgx_enclave_id_t eid, const unsigned char* encrypted_rsa_id, size_t buf_len)
{
	sgx_status_t status;
	ms_provision_rsa_id_t ms;
	ms.ms_encrypted_rsa_id = (unsigned char*)encrypted_rsa_id;
	ms.ms_buf_len = buf_len;
	status = sgx_ecall(eid, 10, &ocall_table_Enclave, &ms);
	return status;
}

sgx_status_t dummy(sgx_enclave_id_t eid)
{
	sgx_status_t status;
	status = sgx_ecall(eid, 11, &ocall_table_Enclave, NULL);
	return status;
}

