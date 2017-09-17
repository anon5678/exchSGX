#ifndef ENCLAVE_ECDSA_H
#define ENCLAVE_ECDSA_H

#include <string>
#include <sgx_tseal.h>
#include <mbedtls/pk.h>

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

int provision_rsa_id(const unsigned char *secret_key, size_t secret_key_len, const char *cert_pem);

int query_rsa_pubkey(unsigned char *o_pubkey, size_t cap_pubkey, char* o_cert_pem, size_t cap_cert_pem);

extern std::string g_cert_pem;
extern mbedtls_pk_context g_rsa_sk;


#if defined(__cplusplus)
}
#endif
#endif