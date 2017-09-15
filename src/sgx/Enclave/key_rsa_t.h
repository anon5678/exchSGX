#include <sgx_tseal.h>

#ifndef ENCLAVE_ECDSA_H
#define ENCLAVE_ECDSA_H

#if defined(__cplusplus)
extern "C" {
#endif
/*
 * ECALL interface
 */
int rsa_keygen_in_seal(const char* subject_name,
                       unsigned char *o_sealed, size_t cap_sealed,
                       unsigned char *o_pubkey, size_t cap_pubkey,
                       unsigned char *o_csr, size_t cap_csr);

int unseal_secret_and_leak_public_key(const sgx_sealed_data_t *secret,
                                      size_t secret_len, unsigned char *pubkey,
                                      size_t cap_pubkey);

int provision_rsa_id(const unsigned char *secret, size_t secret_len);

int query_rsa_pubkey(unsigned char *pubkey, size_t cap_pubkey);

#if defined(__cplusplus)
}
#endif
#endif