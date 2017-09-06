#include <sgx_tseal.h>
#include <string.h>
#include <stdexcept>
#include <string>

using std::runtime_error;

#include "key_t.h"
#include "log.h"
#include "../common/errno.h"

#include "mbedtls/config.h"
#include "mbedtls/bignum.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/ecdsa.h"
#include "mbedtls/entropy.h"
#include "mbedtls/error.h"

#define ECPARAMS MBEDTLS_ECP_DP_SECP256K1

static int __ecdsa_seckey_to_pubkey(const mbedtls_mpi *seckey, unsigned char *pubkey);

// pubkey: 64 Bytes
// SHA3-256: 32 Bytes
// use lower 160 bits as address
/*
---- ADDRESS -------------------------------
SEC: cd244b3015703ddf545595da06ada5516628c5feadbf49dc66049c4b370cc5d8
PUB:
bb48ae3726c5737344a54b3463fec499cb108a7d11ba137ba3c7d043bd6d7e14994f60462a3f91550749bb2ae5411f22b7f9bee79956a463c308ad508f3557df
ADR: 89b44e4d3c81ede05d0f5de8d1a68f754d73d997
*/

#define PREDEFINED_SECKEY "cd244b3015703ddf545595da06ada5516628c5feadbf49dc66049c4b370cc5d8"

/*!
 * generate a new key pair and return the sealed secret key, the public key and
 * the address
 * @param o_sealed
 * @param olen
 * @param o_pubkey
 * @return
 */
int keygen_in_seal(unsigned char *o_sealed, size_t *olen, unsigned char *o_pubkey) {
  int ret = 0;

  mbedtls_mpi secret;
  mbedtls_mpi_init(&secret);

  mbedtls_ecp_group grp;
  mbedtls_ecp_group_init(&grp);
  mbedtls_ecp_group_load(&grp, ECPARAMS);

#ifdef PREDEFINED_SECKEY
  LL_CRITICAL("*** PREDEFINED SECRET KEY IS USED ***");
  LL_CRITICAL("*** DISABLE THIS BEFORE DEPLOY ***");
  ret = mbedtls_mpi_read_string(&secret, 16, PREDEFINED_SECKEY);
  if (ret != 0) {
    LL_CRITICAL("Error: mbedtls_mpi_read_string returned %d", ret);
    return -1;
  }
#else
  mbedtls_mpi_fill_random(&secret, grp.nbits / 8, mbedtls_sgx_drbg_random,
                          NULL);
#endif

  unsigned char secret_buffer[32];
  if (mbedtls_mpi_write_binary(&secret, secret_buffer, sizeof secret_buffer) != 0) {
    LL_CRITICAL("can't run secret to buffer");
    ret = -1;
    goto exit;
  }

  // seal the data
  {
    uint32_t len = sgx_calc_sealed_data_size(0, sizeof(secret_buffer));
    auto *seal_buffer = (sgx_sealed_data_t *) malloc(len);
    LL_LOG("sealed secret length is %d", len);

    auto st = sgx_seal_data(0, nullptr, sizeof secret_buffer, secret_buffer, len, seal_buffer);
    if (st != SGX_SUCCESS) {
      LL_LOG("Failed to seal. Ecall returned %d", st);
      ret = -1;
      goto exit;
    }

    *olen = len;
    memcpy(o_sealed, seal_buffer, len);
    free(seal_buffer);
  }

  if (__ecdsa_seckey_to_pubkey(&secret, o_pubkey) != 0) {
    LL_CRITICAL("failed to get public key");
    ret = -1;
    goto exit;
  }

  exit:
  mbedtls_mpi_free(&secret);
  mbedtls_ecp_group_free(&grp);
  return ret;
}


/*!
 * recover (unseal) the public key and address from the sealed secret key.
 * @param secret
 * @param secret_len
 * @param pubkey
 * @return
 */
int unseal_secret_and_leak_public_key(const sgx_sealed_data_t *secret, size_t secret_len, unsigned char *pubkey) {
  // used by edge8r
  (void) secret_len;

  uint32_t decrypted_text_length = sgx_get_encrypt_txt_len(secret);
  uint8_t y[decrypted_text_length];
  sgx_status_t st;

  st = sgx_unseal_data(secret, nullptr, nullptr, y, &decrypted_text_length);
  if (st != SGX_SUCCESS) {
    LL_CRITICAL("unseal returned %x", st);
    return -1;
  }

  // initialize the local secret key
  mbedtls_mpi secret_key;
  mbedtls_mpi_init(&secret_key);
  mbedtls_mpi_read_binary(&secret_key, y, sizeof y);

  return __ecdsa_seckey_to_pubkey(&secret_key, pubkey);
}

static int __ecdsa_seckey_to_pubkey(const mbedtls_mpi *seckey, unsigned char *pubkey) {
  if (pubkey == nullptr || seckey == nullptr) {
    return -1;
  }

  int ret;
  size_t buflen = 0;

  mbedtls_ecdsa_context ctx;
  mbedtls_ecdsa_init(&ctx);
  mbedtls_ecp_group_load(&ctx.grp, ECPARAMS);

  mbedtls_mpi_copy(&ctx.d, seckey);

  ret = mbedtls_ecp_mul(&ctx.grp, &ctx.Q, &ctx.d, &ctx.grp.G, NULL, NULL);
  if (ret != 0) {
    LL_CRITICAL("Error: mbedtls_ecp_mul returned %d", ret);
    return -1;
  }

  ret = mbedtls_ecp_point_write_binary(
      &ctx.grp, &ctx.Q, MBEDTLS_ECP_PF_UNCOMPRESSED, &buflen, pubkey, PUBKEY_LEN);
  if (ret == MBEDTLS_ERR_ECP_BUFFER_TOO_SMALL) {
    LL_CRITICAL("buffer too small");
    return -1;
  } else if (ret == MBEDTLS_ERR_ECP_BAD_INPUT_DATA) {
    LL_CRITICAL("bad input data");
    return -1;
  }
  if (buflen != PUBKEY_LEN) {
    LL_CRITICAL("ecp serialization is incorrect olen=%ld", buflen);
  }

  return 0;
}