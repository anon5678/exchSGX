#include "test_u.h"
#include <errno.h>

typedef struct ms_enclaveTest_t {
	int ms_retval;
} ms_enclaveTest_t;

typedef struct ms_ocall_print_to_std_t {
	int ms_retval;
	char* ms_str;
} ms_ocall_print_to_std_t;

typedef struct ms_ocall_print_to_err_t {
	int ms_retval;
	char* ms_str;
} ms_ocall_print_to_err_t;

static sgx_status_t SGX_CDECL test_ocall_print_to_std(void* pms)
{
	ms_ocall_print_to_std_t* ms = SGX_CAST(ms_ocall_print_to_std_t*, pms);
	ms->ms_retval = ocall_print_to_std((const char*)ms->ms_str);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL test_ocall_print_to_err(void* pms)
{
	ms_ocall_print_to_err_t* ms = SGX_CAST(ms_ocall_print_to_err_t*, pms);
	ms->ms_retval = ocall_print_to_err((const char*)ms->ms_str);

	return SGX_SUCCESS;
}

static const struct {
	size_t nr_ocall;
	void * table[2];
} ocall_table_test = {
	2,
	{
		(void*)test_ocall_print_to_std,
		(void*)test_ocall_print_to_err,
	}
};
sgx_status_t enclaveTest(sgx_enclave_id_t eid, int* retval)
{
	sgx_status_t status;
	ms_enclaveTest_t ms;
	status = sgx_ecall(eid, 0, &ocall_table_test, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

