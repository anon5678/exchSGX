#include "Enclave_t.h"

#include "sgx_trts.h" /* for sgx_ocalloc, sgx_is_outside_enclave */

#include <errno.h>
#include <string.h> /* for memcpy etc */
#include <stdlib.h> /* for malloc/free etc */

#define CHECK_REF_POINTER(ptr, siz) do {	\
	if (!(ptr) || ! sgx_is_outside_enclave((ptr), (siz)))	\
		return SGX_ERROR_INVALID_PARAMETER;\
} while (0)

#define CHECK_UNIQUE_POINTER(ptr, siz) do {	\
	if ((ptr) && ! sgx_is_outside_enclave((ptr), (siz)))	\
		return SGX_ERROR_INVALID_PARAMETER;\
} while (0)


typedef struct ms_ecall_bitcoin_deposit_t {
	int ms_retval;
	bitcoin_deposit_t* ms_deposit;
} ms_ecall_bitcoin_deposit_t;

typedef struct ms_enclaveTest_t {
	int ms_retval;
} ms_enclaveTest_t;

typedef struct ms_ecall_append_block_to_fifo_t {
	int ms_retval;
	char* ms_blockHeaderHex;
} ms_ecall_append_block_to_fifo_t;

typedef struct ms_rsa_keygen_in_seal_t {
	int ms_retval;
	char* ms_subject_name;
	unsigned char* ms_o_sealed;
	size_t ms_cap_sealed;
	unsigned char* ms_o_pubkey;
	size_t ms_cap_pubkey;
	unsigned char* ms_o_csr;
	size_t ms_cap_csr;
} ms_rsa_keygen_in_seal_t;

typedef struct ms_unseal_secret_and_leak_public_key_t {
	int ms_retval;
	sgx_sealed_data_t* ms_secret;
	size_t ms_secret_len;
	unsigned char* ms_pubkey;
	size_t ms_cap_pubkey;
} ms_unseal_secret_and_leak_public_key_t;

typedef struct ms_provision_rsa_id_t {
	int ms_retval;
	unsigned char* ms_sealed_rsa_secret_key;
	size_t ms_secret_len;
	char* ms_cert_pem;
} ms_provision_rsa_id_t;

typedef struct ms_query_rsa_pubkey_t {
	int ms_retval;
	unsigned char* ms_pubkey;
	size_t ms_cap_pubkey;
	char* ms_cert_pem;
	size_t ms_cap_cert_pem;
} ms_query_rsa_pubkey_t;

typedef struct ms_merkle_proof_verify_t {
	int ms_retval;
	merkle_proof_t* ms_proof;
} ms_merkle_proof_verify_t;

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

static sgx_status_t SGX_CDECL sgx_ecall_bitcoin_deposit(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_ecall_bitcoin_deposit_t));
	ms_ecall_bitcoin_deposit_t* ms = SGX_CAST(ms_ecall_bitcoin_deposit_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	bitcoin_deposit_t* _tmp_deposit = ms->ms_deposit;



	//
	// fence after pointer checks
	//
	__builtin_ia32_lfence();


	ms->ms_retval = ecall_bitcoin_deposit((const bitcoin_deposit_t*)_tmp_deposit);


	return status;
}

static sgx_status_t SGX_CDECL sgx_onMessageFromFairnessLeader(void* pms)
{
	sgx_status_t status = SGX_SUCCESS;
	if (pms != NULL) return SGX_ERROR_INVALID_PARAMETER;
	onMessageFromFairnessLeader();
	return status;
}

static sgx_status_t SGX_CDECL sgx_onAckFromFairnessFollower(void* pms)
{
	sgx_status_t status = SGX_SUCCESS;
	if (pms != NULL) return SGX_ERROR_INVALID_PARAMETER;
	onAckFromFairnessFollower();
	return status;
}

static sgx_status_t SGX_CDECL sgx_enclaveTest(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_enclaveTest_t));
	ms_enclaveTest_t* ms = SGX_CAST(ms_enclaveTest_t*, pms);
	sgx_status_t status = SGX_SUCCESS;



	//
	// fence after pointer checks
	//
	__builtin_ia32_lfence();


	ms->ms_retval = enclaveTest();


	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_append_block_to_fifo(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_ecall_append_block_to_fifo_t));
	ms_ecall_append_block_to_fifo_t* ms = SGX_CAST(ms_ecall_append_block_to_fifo_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	char* _tmp_blockHeaderHex = ms->ms_blockHeaderHex;
	size_t _len_blockHeaderHex = _tmp_blockHeaderHex ? strlen(_tmp_blockHeaderHex) + 1 : 0;
	char* _in_blockHeaderHex = NULL;

	CHECK_UNIQUE_POINTER(_tmp_blockHeaderHex, _len_blockHeaderHex);


	//
	// fence after pointer checks
	//
	__builtin_ia32_lfence();

	if (_tmp_blockHeaderHex != NULL && _len_blockHeaderHex != 0) {
		_in_blockHeaderHex = (char*)malloc(_len_blockHeaderHex);
		if (_in_blockHeaderHex == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memcpy((void*)_in_blockHeaderHex, _tmp_blockHeaderHex, _len_blockHeaderHex);
		_in_blockHeaderHex[_len_blockHeaderHex - 1] = '\0';
	}

	ms->ms_retval = ecall_append_block_to_fifo((const char*)_in_blockHeaderHex);
err:
	if (_in_blockHeaderHex) free((void*)_in_blockHeaderHex);

	return status;
}

static sgx_status_t SGX_CDECL sgx_rsa_keygen_in_seal(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_rsa_keygen_in_seal_t));
	ms_rsa_keygen_in_seal_t* ms = SGX_CAST(ms_rsa_keygen_in_seal_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	char* _tmp_subject_name = ms->ms_subject_name;
	size_t _len_subject_name = _tmp_subject_name ? strlen(_tmp_subject_name) + 1 : 0;
	char* _in_subject_name = NULL;
	unsigned char* _tmp_o_sealed = ms->ms_o_sealed;
	unsigned char* _tmp_o_pubkey = ms->ms_o_pubkey;
	unsigned char* _tmp_o_csr = ms->ms_o_csr;

	CHECK_UNIQUE_POINTER(_tmp_subject_name, _len_subject_name);


	//
	// fence after pointer checks
	//
	__builtin_ia32_lfence();

	if (_tmp_subject_name != NULL && _len_subject_name != 0) {
		_in_subject_name = (char*)malloc(_len_subject_name);
		if (_in_subject_name == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memcpy((void*)_in_subject_name, _tmp_subject_name, _len_subject_name);
		_in_subject_name[_len_subject_name - 1] = '\0';
	}

	ms->ms_retval = rsa_keygen_in_seal((const char*)_in_subject_name, _tmp_o_sealed, ms->ms_cap_sealed, _tmp_o_pubkey, ms->ms_cap_pubkey, _tmp_o_csr, ms->ms_cap_csr);
err:
	if (_in_subject_name) free((void*)_in_subject_name);

	return status;
}

static sgx_status_t SGX_CDECL sgx_unseal_secret_and_leak_public_key(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_unseal_secret_and_leak_public_key_t));
	ms_unseal_secret_and_leak_public_key_t* ms = SGX_CAST(ms_unseal_secret_and_leak_public_key_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	sgx_sealed_data_t* _tmp_secret = ms->ms_secret;
	size_t _tmp_secret_len = ms->ms_secret_len;
	size_t _len_secret = _tmp_secret_len;
	sgx_sealed_data_t* _in_secret = NULL;
	unsigned char* _tmp_pubkey = ms->ms_pubkey;

	CHECK_UNIQUE_POINTER(_tmp_secret, _len_secret);


	//
	// fence after pointer checks
	//
	__builtin_ia32_lfence();

	if (_tmp_secret != NULL && _len_secret != 0) {
		_in_secret = (sgx_sealed_data_t*)malloc(_len_secret);
		if (_in_secret == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memcpy((void*)_in_secret, _tmp_secret, _len_secret);
	}

	ms->ms_retval = unseal_secret_and_leak_public_key((const sgx_sealed_data_t*)_in_secret, _tmp_secret_len, _tmp_pubkey, ms->ms_cap_pubkey);
err:
	if (_in_secret) free((void*)_in_secret);

	return status;
}

static sgx_status_t SGX_CDECL sgx_provision_rsa_id(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_provision_rsa_id_t));
	ms_provision_rsa_id_t* ms = SGX_CAST(ms_provision_rsa_id_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	unsigned char* _tmp_sealed_rsa_secret_key = ms->ms_sealed_rsa_secret_key;
	size_t _tmp_secret_len = ms->ms_secret_len;
	size_t _len_sealed_rsa_secret_key = _tmp_secret_len;
	unsigned char* _in_sealed_rsa_secret_key = NULL;
	char* _tmp_cert_pem = ms->ms_cert_pem;
	size_t _len_cert_pem = _tmp_cert_pem ? strlen(_tmp_cert_pem) + 1 : 0;
	char* _in_cert_pem = NULL;

	CHECK_UNIQUE_POINTER(_tmp_sealed_rsa_secret_key, _len_sealed_rsa_secret_key);
	CHECK_UNIQUE_POINTER(_tmp_cert_pem, _len_cert_pem);


	//
	// fence after pointer checks
	//
	__builtin_ia32_lfence();

	if (_tmp_sealed_rsa_secret_key != NULL && _len_sealed_rsa_secret_key != 0) {
		_in_sealed_rsa_secret_key = (unsigned char*)malloc(_len_sealed_rsa_secret_key);
		if (_in_sealed_rsa_secret_key == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memcpy((void*)_in_sealed_rsa_secret_key, _tmp_sealed_rsa_secret_key, _len_sealed_rsa_secret_key);
	}
	if (_tmp_cert_pem != NULL && _len_cert_pem != 0) {
		_in_cert_pem = (char*)malloc(_len_cert_pem);
		if (_in_cert_pem == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memcpy((void*)_in_cert_pem, _tmp_cert_pem, _len_cert_pem);
		_in_cert_pem[_len_cert_pem - 1] = '\0';
	}

	ms->ms_retval = provision_rsa_id((const unsigned char*)_in_sealed_rsa_secret_key, _tmp_secret_len, (const char*)_in_cert_pem);
err:
	if (_in_sealed_rsa_secret_key) free((void*)_in_sealed_rsa_secret_key);
	if (_in_cert_pem) free((void*)_in_cert_pem);

	return status;
}

static sgx_status_t SGX_CDECL sgx_query_rsa_pubkey(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_query_rsa_pubkey_t));
	ms_query_rsa_pubkey_t* ms = SGX_CAST(ms_query_rsa_pubkey_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	unsigned char* _tmp_pubkey = ms->ms_pubkey;
	char* _tmp_cert_pem = ms->ms_cert_pem;



	//
	// fence after pointer checks
	//
	__builtin_ia32_lfence();


	ms->ms_retval = query_rsa_pubkey(_tmp_pubkey, ms->ms_cap_pubkey, _tmp_cert_pem, ms->ms_cap_cert_pem);


	return status;
}

static sgx_status_t SGX_CDECL sgx_merkle_proof_verify(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_merkle_proof_verify_t));
	ms_merkle_proof_verify_t* ms = SGX_CAST(ms_merkle_proof_verify_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	merkle_proof_t* _tmp_proof = ms->ms_proof;



	//
	// fence after pointer checks
	//
	__builtin_ia32_lfence();


	ms->ms_retval = merkle_proof_verify((const merkle_proof_t*)_tmp_proof);


	return status;
}

static sgx_status_t SGX_CDECL sgx_dummy(void* pms)
{
	sgx_status_t status = SGX_SUCCESS;
	if (pms != NULL) return SGX_ERROR_INVALID_PARAMETER;
	dummy();
	return status;
}

SGX_EXTERNC const struct {
	size_t nr_ecall;
	struct {void* ecall_addr; uint8_t is_priv;} ecall_table[11];
} g_ecall_table = {
	11,
	{
		{(void*)(uintptr_t)sgx_ecall_bitcoin_deposit, 0},
		{(void*)(uintptr_t)sgx_onMessageFromFairnessLeader, 0},
		{(void*)(uintptr_t)sgx_onAckFromFairnessFollower, 0},
		{(void*)(uintptr_t)sgx_enclaveTest, 0},
		{(void*)(uintptr_t)sgx_ecall_append_block_to_fifo, 0},
		{(void*)(uintptr_t)sgx_rsa_keygen_in_seal, 0},
		{(void*)(uintptr_t)sgx_unseal_secret_and_leak_public_key, 0},
		{(void*)(uintptr_t)sgx_provision_rsa_id, 0},
		{(void*)(uintptr_t)sgx_query_rsa_pubkey, 0},
		{(void*)(uintptr_t)sgx_merkle_proof_verify, 0},
		{(void*)(uintptr_t)sgx_dummy, 0},
	}
};

SGX_EXTERNC const struct {
	size_t nr_ocall;
	uint8_t entry_table[20][11];
} g_dyn_entry_table = {
	20,
	{
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
	}
};


sgx_status_t SGX_CDECL sendMessagesToFairnessFollowers()
{
	sgx_status_t status = SGX_SUCCESS;
	status = sgx_ocall(0, NULL);

	return status;
}

sgx_status_t SGX_CDECL settle()
{
	sgx_status_t status = SGX_SUCCESS;
	status = sgx_ocall(1, NULL);

	return status;
}

sgx_status_t SGX_CDECL ocall_mbedtls_net_connect(int* retval, mbedtls_net_context* ctx, const char* host, const char* port, int proto)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_ctx = sizeof(*ctx);
	size_t _len_host = host ? strlen(host) + 1 : 0;
	size_t _len_port = port ? strlen(port) + 1 : 0;

	ms_ocall_mbedtls_net_connect_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_mbedtls_net_connect_t);
	void *__tmp = NULL;

	void *__tmp_ctx = NULL;
	ocalloc_size += (ctx != NULL && sgx_is_within_enclave(ctx, _len_ctx)) ? _len_ctx : 0;
	ocalloc_size += (host != NULL && sgx_is_within_enclave(host, _len_host)) ? _len_host : 0;
	ocalloc_size += (port != NULL && sgx_is_within_enclave(port, _len_port)) ? _len_port : 0;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_mbedtls_net_connect_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_mbedtls_net_connect_t));

	if (ctx != NULL && sgx_is_within_enclave(ctx, _len_ctx)) {
		ms->ms_ctx = (mbedtls_net_context*)__tmp;
		__tmp_ctx = __tmp;
		memcpy(__tmp_ctx, ctx, _len_ctx);
		__tmp = (void *)((size_t)__tmp + _len_ctx);
	} else if (ctx == NULL) {
		ms->ms_ctx = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	if (host != NULL && sgx_is_within_enclave(host, _len_host)) {
		ms->ms_host = (char*)__tmp;
		memcpy(__tmp, host, _len_host);
		__tmp = (void *)((size_t)__tmp + _len_host);
	} else if (host == NULL) {
		ms->ms_host = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	if (port != NULL && sgx_is_within_enclave(port, _len_port)) {
		ms->ms_port = (char*)__tmp;
		memcpy(__tmp, port, _len_port);
		__tmp = (void *)((size_t)__tmp + _len_port);
	} else if (port == NULL) {
		ms->ms_port = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	ms->ms_proto = proto;
	status = sgx_ocall(2, ms);

	if (retval) *retval = ms->ms_retval;
	if (ctx) memcpy((void*)ctx, __tmp_ctx, _len_ctx);

	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_mbedtls_net_bind(int* retval, mbedtls_net_context* ctx, const char* bind_ip, const char* port, int proto)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_ctx = sizeof(*ctx);
	size_t _len_bind_ip = bind_ip ? strlen(bind_ip) + 1 : 0;
	size_t _len_port = port ? strlen(port) + 1 : 0;

	ms_ocall_mbedtls_net_bind_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_mbedtls_net_bind_t);
	void *__tmp = NULL;

	void *__tmp_ctx = NULL;
	ocalloc_size += (ctx != NULL && sgx_is_within_enclave(ctx, _len_ctx)) ? _len_ctx : 0;
	ocalloc_size += (bind_ip != NULL && sgx_is_within_enclave(bind_ip, _len_bind_ip)) ? _len_bind_ip : 0;
	ocalloc_size += (port != NULL && sgx_is_within_enclave(port, _len_port)) ? _len_port : 0;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_mbedtls_net_bind_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_mbedtls_net_bind_t));

	if (ctx != NULL && sgx_is_within_enclave(ctx, _len_ctx)) {
		ms->ms_ctx = (mbedtls_net_context*)__tmp;
		__tmp_ctx = __tmp;
		memset(__tmp_ctx, 0, _len_ctx);
		__tmp = (void *)((size_t)__tmp + _len_ctx);
	} else if (ctx == NULL) {
		ms->ms_ctx = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	if (bind_ip != NULL && sgx_is_within_enclave(bind_ip, _len_bind_ip)) {
		ms->ms_bind_ip = (char*)__tmp;
		memcpy(__tmp, bind_ip, _len_bind_ip);
		__tmp = (void *)((size_t)__tmp + _len_bind_ip);
	} else if (bind_ip == NULL) {
		ms->ms_bind_ip = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	if (port != NULL && sgx_is_within_enclave(port, _len_port)) {
		ms->ms_port = (char*)__tmp;
		memcpy(__tmp, port, _len_port);
		__tmp = (void *)((size_t)__tmp + _len_port);
	} else if (port == NULL) {
		ms->ms_port = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	ms->ms_proto = proto;
	status = sgx_ocall(3, ms);

	if (retval) *retval = ms->ms_retval;
	if (ctx) memcpy((void*)ctx, __tmp_ctx, _len_ctx);

	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_mbedtls_net_accept(int* retval, mbedtls_net_context* bind_ctx, mbedtls_net_context* client_ctx, void* client_ip, size_t buf_size, size_t* ip_len)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_bind_ctx = sizeof(*bind_ctx);
	size_t _len_client_ctx = sizeof(*client_ctx);
	size_t _len_client_ip = buf_size;
	size_t _len_ip_len = sizeof(*ip_len);

	ms_ocall_mbedtls_net_accept_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_mbedtls_net_accept_t);
	void *__tmp = NULL;

	void *__tmp_client_ctx = NULL;
	void *__tmp_client_ip = NULL;
	void *__tmp_ip_len = NULL;
	ocalloc_size += (bind_ctx != NULL && sgx_is_within_enclave(bind_ctx, _len_bind_ctx)) ? _len_bind_ctx : 0;
	ocalloc_size += (client_ctx != NULL && sgx_is_within_enclave(client_ctx, _len_client_ctx)) ? _len_client_ctx : 0;
	ocalloc_size += (client_ip != NULL && sgx_is_within_enclave(client_ip, _len_client_ip)) ? _len_client_ip : 0;
	ocalloc_size += (ip_len != NULL && sgx_is_within_enclave(ip_len, _len_ip_len)) ? _len_ip_len : 0;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_mbedtls_net_accept_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_mbedtls_net_accept_t));

	if (bind_ctx != NULL && sgx_is_within_enclave(bind_ctx, _len_bind_ctx)) {
		ms->ms_bind_ctx = (mbedtls_net_context*)__tmp;
		memcpy(__tmp, bind_ctx, _len_bind_ctx);
		__tmp = (void *)((size_t)__tmp + _len_bind_ctx);
	} else if (bind_ctx == NULL) {
		ms->ms_bind_ctx = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	if (client_ctx != NULL && sgx_is_within_enclave(client_ctx, _len_client_ctx)) {
		ms->ms_client_ctx = (mbedtls_net_context*)__tmp;
		__tmp_client_ctx = __tmp;
		memset(__tmp_client_ctx, 0, _len_client_ctx);
		__tmp = (void *)((size_t)__tmp + _len_client_ctx);
	} else if (client_ctx == NULL) {
		ms->ms_client_ctx = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	if (client_ip != NULL && sgx_is_within_enclave(client_ip, _len_client_ip)) {
		ms->ms_client_ip = (void*)__tmp;
		__tmp_client_ip = __tmp;
		memset(__tmp_client_ip, 0, _len_client_ip);
		__tmp = (void *)((size_t)__tmp + _len_client_ip);
	} else if (client_ip == NULL) {
		ms->ms_client_ip = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	ms->ms_buf_size = buf_size;
	if (ip_len != NULL && sgx_is_within_enclave(ip_len, _len_ip_len)) {
		ms->ms_ip_len = (size_t*)__tmp;
		__tmp_ip_len = __tmp;
		memset(__tmp_ip_len, 0, _len_ip_len);
		__tmp = (void *)((size_t)__tmp + _len_ip_len);
	} else if (ip_len == NULL) {
		ms->ms_ip_len = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	status = sgx_ocall(4, ms);

	if (retval) *retval = ms->ms_retval;
	if (client_ctx) memcpy((void*)client_ctx, __tmp_client_ctx, _len_client_ctx);
	if (client_ip) memcpy((void*)client_ip, __tmp_client_ip, _len_client_ip);
	if (ip_len) memcpy((void*)ip_len, __tmp_ip_len, _len_ip_len);

	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_mbedtls_net_set_block(int* retval, mbedtls_net_context* ctx)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_ctx = sizeof(*ctx);

	ms_ocall_mbedtls_net_set_block_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_mbedtls_net_set_block_t);
	void *__tmp = NULL;

	void *__tmp_ctx = NULL;
	ocalloc_size += (ctx != NULL && sgx_is_within_enclave(ctx, _len_ctx)) ? _len_ctx : 0;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_mbedtls_net_set_block_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_mbedtls_net_set_block_t));

	if (ctx != NULL && sgx_is_within_enclave(ctx, _len_ctx)) {
		ms->ms_ctx = (mbedtls_net_context*)__tmp;
		__tmp_ctx = __tmp;
		memcpy(__tmp_ctx, ctx, _len_ctx);
		__tmp = (void *)((size_t)__tmp + _len_ctx);
	} else if (ctx == NULL) {
		ms->ms_ctx = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	status = sgx_ocall(5, ms);

	if (retval) *retval = ms->ms_retval;
	if (ctx) memcpy((void*)ctx, __tmp_ctx, _len_ctx);

	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_mbedtls_net_set_nonblock(int* retval, mbedtls_net_context* ctx)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_ctx = sizeof(*ctx);

	ms_ocall_mbedtls_net_set_nonblock_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_mbedtls_net_set_nonblock_t);
	void *__tmp = NULL;

	void *__tmp_ctx = NULL;
	ocalloc_size += (ctx != NULL && sgx_is_within_enclave(ctx, _len_ctx)) ? _len_ctx : 0;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_mbedtls_net_set_nonblock_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_mbedtls_net_set_nonblock_t));

	if (ctx != NULL && sgx_is_within_enclave(ctx, _len_ctx)) {
		ms->ms_ctx = (mbedtls_net_context*)__tmp;
		__tmp_ctx = __tmp;
		memcpy(__tmp_ctx, ctx, _len_ctx);
		__tmp = (void *)((size_t)__tmp + _len_ctx);
	} else if (ctx == NULL) {
		ms->ms_ctx = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	status = sgx_ocall(6, ms);

	if (retval) *retval = ms->ms_retval;
	if (ctx) memcpy((void*)ctx, __tmp_ctx, _len_ctx);

	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_mbedtls_net_usleep(unsigned long int usec)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_ocall_mbedtls_net_usleep_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_mbedtls_net_usleep_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_mbedtls_net_usleep_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_mbedtls_net_usleep_t));

	ms->ms_usec = usec;
	status = sgx_ocall(7, ms);


	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_mbedtls_net_recv(int* retval, mbedtls_net_context* ctx, unsigned char* buf, size_t len)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_ctx = sizeof(*ctx);
	size_t _len_buf = len;

	ms_ocall_mbedtls_net_recv_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_mbedtls_net_recv_t);
	void *__tmp = NULL;

	void *__tmp_ctx = NULL;
	void *__tmp_buf = NULL;
	ocalloc_size += (ctx != NULL && sgx_is_within_enclave(ctx, _len_ctx)) ? _len_ctx : 0;
	ocalloc_size += (buf != NULL && sgx_is_within_enclave(buf, _len_buf)) ? _len_buf : 0;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_mbedtls_net_recv_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_mbedtls_net_recv_t));

	if (ctx != NULL && sgx_is_within_enclave(ctx, _len_ctx)) {
		ms->ms_ctx = (mbedtls_net_context*)__tmp;
		__tmp_ctx = __tmp;
		memcpy(__tmp_ctx, ctx, _len_ctx);
		__tmp = (void *)((size_t)__tmp + _len_ctx);
	} else if (ctx == NULL) {
		ms->ms_ctx = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	if (buf != NULL && sgx_is_within_enclave(buf, _len_buf)) {
		ms->ms_buf = (unsigned char*)__tmp;
		__tmp_buf = __tmp;
		memset(__tmp_buf, 0, _len_buf);
		__tmp = (void *)((size_t)__tmp + _len_buf);
	} else if (buf == NULL) {
		ms->ms_buf = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	ms->ms_len = len;
	status = sgx_ocall(8, ms);

	if (retval) *retval = ms->ms_retval;
	if (ctx) memcpy((void*)ctx, __tmp_ctx, _len_ctx);
	if (buf) memcpy((void*)buf, __tmp_buf, _len_buf);

	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_mbedtls_net_send(int* retval, mbedtls_net_context* ctx, const unsigned char* buf, size_t len)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_ctx = sizeof(*ctx);
	size_t _len_buf = len;

	ms_ocall_mbedtls_net_send_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_mbedtls_net_send_t);
	void *__tmp = NULL;

	void *__tmp_ctx = NULL;
	ocalloc_size += (ctx != NULL && sgx_is_within_enclave(ctx, _len_ctx)) ? _len_ctx : 0;
	ocalloc_size += (buf != NULL && sgx_is_within_enclave(buf, _len_buf)) ? _len_buf : 0;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_mbedtls_net_send_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_mbedtls_net_send_t));

	if (ctx != NULL && sgx_is_within_enclave(ctx, _len_ctx)) {
		ms->ms_ctx = (mbedtls_net_context*)__tmp;
		__tmp_ctx = __tmp;
		memcpy(__tmp_ctx, ctx, _len_ctx);
		__tmp = (void *)((size_t)__tmp + _len_ctx);
	} else if (ctx == NULL) {
		ms->ms_ctx = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	if (buf != NULL && sgx_is_within_enclave(buf, _len_buf)) {
		ms->ms_buf = (unsigned char*)__tmp;
		memcpy(__tmp, buf, _len_buf);
		__tmp = (void *)((size_t)__tmp + _len_buf);
	} else if (buf == NULL) {
		ms->ms_buf = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	ms->ms_len = len;
	status = sgx_ocall(9, ms);

	if (retval) *retval = ms->ms_retval;
	if (ctx) memcpy((void*)ctx, __tmp_ctx, _len_ctx);

	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_mbedtls_net_recv_timeout(int* retval, mbedtls_net_context* ctx, unsigned char* buf, size_t len, uint32_t timeout)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_ctx = sizeof(*ctx);
	size_t _len_buf = len;

	ms_ocall_mbedtls_net_recv_timeout_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_mbedtls_net_recv_timeout_t);
	void *__tmp = NULL;

	void *__tmp_ctx = NULL;
	void *__tmp_buf = NULL;
	ocalloc_size += (ctx != NULL && sgx_is_within_enclave(ctx, _len_ctx)) ? _len_ctx : 0;
	ocalloc_size += (buf != NULL && sgx_is_within_enclave(buf, _len_buf)) ? _len_buf : 0;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_mbedtls_net_recv_timeout_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_mbedtls_net_recv_timeout_t));

	if (ctx != NULL && sgx_is_within_enclave(ctx, _len_ctx)) {
		ms->ms_ctx = (mbedtls_net_context*)__tmp;
		__tmp_ctx = __tmp;
		memcpy(__tmp_ctx, ctx, _len_ctx);
		__tmp = (void *)((size_t)__tmp + _len_ctx);
	} else if (ctx == NULL) {
		ms->ms_ctx = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	if (buf != NULL && sgx_is_within_enclave(buf, _len_buf)) {
		ms->ms_buf = (unsigned char*)__tmp;
		__tmp_buf = __tmp;
		memset(__tmp_buf, 0, _len_buf);
		__tmp = (void *)((size_t)__tmp + _len_buf);
	} else if (buf == NULL) {
		ms->ms_buf = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	ms->ms_len = len;
	ms->ms_timeout = timeout;
	status = sgx_ocall(10, ms);

	if (retval) *retval = ms->ms_retval;
	if (ctx) memcpy((void*)ctx, __tmp_ctx, _len_ctx);
	if (buf) memcpy((void*)buf, __tmp_buf, _len_buf);

	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_mbedtls_net_free(mbedtls_net_context* ctx)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_ctx = sizeof(*ctx);

	ms_ocall_mbedtls_net_free_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_mbedtls_net_free_t);
	void *__tmp = NULL;

	void *__tmp_ctx = NULL;
	ocalloc_size += (ctx != NULL && sgx_is_within_enclave(ctx, _len_ctx)) ? _len_ctx : 0;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_mbedtls_net_free_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_mbedtls_net_free_t));

	if (ctx != NULL && sgx_is_within_enclave(ctx, _len_ctx)) {
		ms->ms_ctx = (mbedtls_net_context*)__tmp;
		__tmp_ctx = __tmp;
		memcpy(__tmp_ctx, ctx, _len_ctx);
		__tmp = (void *)((size_t)__tmp + _len_ctx);
	} else if (ctx == NULL) {
		ms->ms_ctx = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	status = sgx_ocall(11, ms);

	if (ctx) memcpy((void*)ctx, __tmp_ctx, _len_ctx);

	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_print_string(int* retval, const char* str)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_str = str ? strlen(str) + 1 : 0;

	ms_ocall_print_string_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_print_string_t);
	void *__tmp = NULL;

	ocalloc_size += (str != NULL && sgx_is_within_enclave(str, _len_str)) ? _len_str : 0;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_print_string_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_print_string_t));

	if (str != NULL && sgx_is_within_enclave(str, _len_str)) {
		ms->ms_str = (char*)__tmp;
		memcpy(__tmp, str, _len_str);
		__tmp = (void *)((size_t)__tmp + _len_str);
	} else if (str == NULL) {
		ms->ms_str = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	status = sgx_ocall(12, ms);

	if (retval) *retval = ms->ms_retval;

	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL sgx_oc_cpuidex(int cpuinfo[4], int leaf, int subleaf)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_cpuinfo = 4 * sizeof(*cpuinfo);

	ms_sgx_oc_cpuidex_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_sgx_oc_cpuidex_t);
	void *__tmp = NULL;

	void *__tmp_cpuinfo = NULL;
	ocalloc_size += (cpuinfo != NULL && sgx_is_within_enclave(cpuinfo, _len_cpuinfo)) ? _len_cpuinfo : 0;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_sgx_oc_cpuidex_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_sgx_oc_cpuidex_t));

	if (cpuinfo != NULL && sgx_is_within_enclave(cpuinfo, _len_cpuinfo)) {
		ms->ms_cpuinfo = (int*)__tmp;
		__tmp_cpuinfo = __tmp;
		memset(__tmp_cpuinfo, 0, _len_cpuinfo);
		__tmp = (void *)((size_t)__tmp + _len_cpuinfo);
	} else if (cpuinfo == NULL) {
		ms->ms_cpuinfo = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	ms->ms_leaf = leaf;
	ms->ms_subleaf = subleaf;
	status = sgx_ocall(13, ms);

	if (cpuinfo) memcpy((void*)cpuinfo, __tmp_cpuinfo, _len_cpuinfo);

	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL sgx_thread_wait_untrusted_event_ocall(int* retval, const void* self)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_sgx_thread_wait_untrusted_event_ocall_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_sgx_thread_wait_untrusted_event_ocall_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_sgx_thread_wait_untrusted_event_ocall_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_sgx_thread_wait_untrusted_event_ocall_t));

	ms->ms_self = SGX_CAST(void*, self);
	status = sgx_ocall(14, ms);

	if (retval) *retval = ms->ms_retval;

	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL sgx_thread_set_untrusted_event_ocall(int* retval, const void* waiter)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_sgx_thread_set_untrusted_event_ocall_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_sgx_thread_set_untrusted_event_ocall_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_sgx_thread_set_untrusted_event_ocall_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_sgx_thread_set_untrusted_event_ocall_t));

	ms->ms_waiter = SGX_CAST(void*, waiter);
	status = sgx_ocall(15, ms);

	if (retval) *retval = ms->ms_retval;

	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL sgx_thread_setwait_untrusted_events_ocall(int* retval, const void* waiter, const void* self)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_sgx_thread_setwait_untrusted_events_ocall_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_sgx_thread_setwait_untrusted_events_ocall_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_sgx_thread_setwait_untrusted_events_ocall_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_sgx_thread_setwait_untrusted_events_ocall_t));

	ms->ms_waiter = SGX_CAST(void*, waiter);
	ms->ms_self = SGX_CAST(void*, self);
	status = sgx_ocall(16, ms);

	if (retval) *retval = ms->ms_retval;

	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL sgx_thread_set_multiple_untrusted_events_ocall(int* retval, const void** waiters, size_t total)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_waiters = total * sizeof(*waiters);

	ms_sgx_thread_set_multiple_untrusted_events_ocall_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_sgx_thread_set_multiple_untrusted_events_ocall_t);
	void *__tmp = NULL;

	ocalloc_size += (waiters != NULL && sgx_is_within_enclave(waiters, _len_waiters)) ? _len_waiters : 0;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_sgx_thread_set_multiple_untrusted_events_ocall_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_sgx_thread_set_multiple_untrusted_events_ocall_t));

	if (waiters != NULL && sgx_is_within_enclave(waiters, _len_waiters)) {
		ms->ms_waiters = (void**)__tmp;
		memcpy(__tmp, waiters, _len_waiters);
		__tmp = (void *)((size_t)__tmp + _len_waiters);
	} else if (waiters == NULL) {
		ms->ms_waiters = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	ms->ms_total = total;
	status = sgx_ocall(17, ms);

	if (retval) *retval = ms->ms_retval;

	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_print_to_std(int* retval, const char* str)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_str = str ? strlen(str) + 1 : 0;

	ms_ocall_print_to_std_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_print_to_std_t);
	void *__tmp = NULL;

	ocalloc_size += (str != NULL && sgx_is_within_enclave(str, _len_str)) ? _len_str : 0;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_print_to_std_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_print_to_std_t));

	if (str != NULL && sgx_is_within_enclave(str, _len_str)) {
		ms->ms_str = (char*)__tmp;
		memcpy(__tmp, str, _len_str);
		__tmp = (void *)((size_t)__tmp + _len_str);
	} else if (str == NULL) {
		ms->ms_str = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	status = sgx_ocall(18, ms);

	if (retval) *retval = ms->ms_retval;

	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_print_to_err(int* retval, const char* str)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_str = str ? strlen(str) + 1 : 0;

	ms_ocall_print_to_err_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_print_to_err_t);
	void *__tmp = NULL;

	ocalloc_size += (str != NULL && sgx_is_within_enclave(str, _len_str)) ? _len_str : 0;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_print_to_err_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_print_to_err_t));

	if (str != NULL && sgx_is_within_enclave(str, _len_str)) {
		ms->ms_str = (char*)__tmp;
		memcpy(__tmp, str, _len_str);
		__tmp = (void *)((size_t)__tmp + _len_str);
	} else if (str == NULL) {
		ms->ms_str = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	status = sgx_ocall(19, ms);

	if (retval) *retval = ms->ms_retval;

	sgx_ocfree();
	return status;
}

