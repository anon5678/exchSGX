#include <sgx_tseal.h>
#include <string.h>
#include <stdexcept>
#include <string>

using std::runtime_error;

#include "key_rsa_t.h"
#include "log.h"
#include "../common/errno.h"

#include "mbedtls/config.h"
#include "mbedtls/bignum.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/rsa.h"
#include "mbedtls/entropy.h"
#include "mbedtls/error.h"

#include "glue.h"

#define ECPARAMS MBEDTLS_ECP_DP_SECP256K1

static int __ecdsa_seckey_to_pubkey(const mbedtls_mpi *seckey, unsigned char *pubkey);

/*!
 * generate a new pair of RSA keys and return the sealed secret key, the public key
 * @param o_sealed
 * @param olen
 * @param o_pubkey
 * @return
 */

#define KEY_SIZE 2048
#define EXPONENT 65537

#include "mbedtls/pk.h"
#include "pprint.h"

int keygen_in_seal(unsigned char *o_sealed, size_t *olen, unsigned char *o_pubkey) {
  int ret = 0;

  mbedtls_pk_context rsa_pk;
  mbedtls_pk_init(&rsa_pk);

  if ((ret = mbedtls_pk_setup(&rsa_pk, mbedtls_pk_info_from_type(MBEDTLS_PK_RSA))) != 0) {
    LL_CRITICAL("failed to setup key: %#x", ret);
    return -1;
  }

  if ((ret = mbedtls_rsa_gen_key(mbedtls_pk_rsa(rsa_pk), mbedtls_sgx_drbg_random, nullptr, KEY_SIZE, EXPONENT)) != 0) {
    LL_CRITICAL("failed to gen key: %#x", ret);
    return -1;
  }

  unsigned char prikey_pem[2000];
  memset(prikey_pem, 0, sizeof prikey_pem);

  ret = mbedtls_pk_write_key_pem(&rsa_pk, prikey_pem, sizeof prikey_pem);
  if (ret != 0) {
      LL_CRITICAL("failed to write secret key: %#x", ret);
      return ret;
  }

  // XXX: hardcode buffer size
  ret = mbedtls_pk_write_pubkey_pem(&rsa_pk, o_pubkey, 1000);
  if (ret != 0) {
      LL_CRITICAL("failed to write secret key: %#x", ret);
      return ret;
  }

  std::string prikey_pem_str(std::string((char*)prikey_pem).c_str());
  LL_NOTICE("RSA PRIVATE KEY:\n%s", prikey_pem_str.c_str());

  // seal the data
  {
    auto len = sgx_calc_sealed_data_size(0, prikey_pem_str.length());
    auto *seal_buffer = (sgx_sealed_data_t *) malloc(len);
    LL_LOG("sealed secret length is %d", len);

    auto st = sgx_seal_data(0, nullptr, prikey_pem_str.length(), (const unsigned char*) prikey_pem_str.c_str(), len, seal_buffer);
    if (st != SGX_SUCCESS) {
      LL_LOG("Failed to seal. Ecall returned %d", st);
      ret = -1;
      goto exit;
    }

    *olen = len;
    memcpy(o_sealed, seal_buffer, len);
    free(seal_buffer);
  }

exit:
  mbedtls_pk_free(&rsa_pk);
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