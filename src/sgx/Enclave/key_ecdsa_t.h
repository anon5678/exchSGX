#include <sgx_tseal.h>

#ifndef ENCLAVE_ECDSA_H
#define ENCLAVE_ECDSA_H

#if defined(__cplusplus)
extern "C" {
#endif
/*
 * ECALL interface
 */
int keygen_in_seal(unsigned char *o_sealed, size_t *olen, unsigned char *o_pubkey);
int unseal_secret_and_leak_public_key(const sgx_sealed_data_t *secret, size_t secret_len, unsigned char *pubkey);
#if defined(__cplusplus)
}
#endif
#endif