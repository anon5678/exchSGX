#include "key_rsa_t.h"

#include <sgx_tseal.h>
#include <stdexcept>
#include <string.h>
#include <string>
#include <vector>

#include "../common/errno.h"
#include "log.h"

#include "mbedtls/bignum.h"
#include "mbedtls/config.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/entropy.h"
#include "mbedtls/error.h"
#include "mbedtls/rsa.h"

#include "glue.h"

#define ECPARAMS MBEDTLS_ECP_DP_SECP256K1

using namespace std;

/*!
 * generate a new pair of RSA keys and return the sealed secret key, the public
 * key
 * @param o_sealed
 * @param olen
 * @param o_pubkey
 * @return
 */

#define KEY_SIZE 2048
#define EXPONENT 65537

#include "mbedtls/pk.h"
#include "pprint.h"

int rsa_keygen_in_seal(unsigned char *o_sealed, size_t cap_sealed,
                       unsigned char *o_pubkey, size_t cap_pubkey) {
  int ret = 0;

  mbedtls_pk_context rsa_pk;
  mbedtls_pk_init(&rsa_pk);

  if ((ret = mbedtls_pk_setup(
           &rsa_pk, mbedtls_pk_info_from_type(MBEDTLS_PK_RSA))) != 0) {
    LL_CRITICAL("failed to setup key: %#x", ret);
    return -1;
  }

  if ((ret =
           mbedtls_rsa_gen_key(mbedtls_pk_rsa(rsa_pk), mbedtls_sgx_drbg_random,
                               nullptr, KEY_SIZE, EXPONENT)) != 0) {
    LL_CRITICAL("failed to gen key: %#x", ret);
    return -1;
  }

  unsigned char prikey_pem[2000];
  memset(prikey_pem, 0, sizeof prikey_pem);

  ret = mbedtls_pk_write_key_pem(&rsa_pk, prikey_pem, sizeof prikey_pem);
  if (ret != 0) {
    LL_CRITICAL("failed to write secret key: %#x", -ret);
    return -1;
  }

  ret = mbedtls_pk_write_pubkey_pem(&rsa_pk, o_pubkey, cap_pubkey);
  if (ret != 0) {
    LL_CRITICAL("failed to write secret key: %#x", -ret);
    return -1;
  }

  size_t prikey_pem_len =
      strlen((const char *)prikey_pem) +
      1; // note that the lenght include the terminating null

  // seal the data
  size_t sealed_len = 0;
  {
    sealed_len = sgx_calc_sealed_data_size(0, prikey_pem_len);
    LL_LOG("sealed secret length is %d", sealed_len);
    if (sealed_len > cap_sealed) {
      LL_CRITICAL("sealed buffer is too small");
      return BUFFER_TOO_SMALL;
    }

    auto *seal_buffer = (sgx_sealed_data_t *)malloc(sealed_len);

    auto st = sgx_seal_data(0, nullptr, prikey_pem_len, prikey_pem, sealed_len,
                            seal_buffer);
    if (st != SGX_SUCCESS) {
      LL_LOG("Failed to seal. Ecall returned %d", st);
      ret = -1;
      goto exit;
    }

    memcpy(o_sealed, seal_buffer, sealed_len);
    free(seal_buffer);
  }

exit:
  mbedtls_pk_free(&rsa_pk);
  return sealed_len;
}

static vector<uint8_t> _sgx_unseal_data_cpp(const sgx_sealed_data_t *secret,
                                            size_t len) {
  // not used
  (void)len;

  uint32_t unsealed_len = sgx_get_encrypt_txt_len(secret);
  uint8_t y[unsealed_len];
  sgx_status_t st;

  st = sgx_unseal_data(secret, nullptr, nullptr, y, &unsealed_len);
  if (st != SGX_SUCCESS) {
    throw runtime_error("unseal returned " + to_string(st));
  }

  return vector<uint8_t>(y, y + sizeof y);
}

/*!
 * recover (unseal) the public key and address from the sealed secret key.
 * @param secret
 * @param secret_len
 * @param pubkey
 * @return
 */
int unseal_secret_and_leak_public_key(const sgx_sealed_data_t *secret,
                                      size_t secret_len, unsigned char *pubkey,
                                      size_t cap_pubkey) {
  int ret;

  vector<uint8_t> unsealed = _sgx_unseal_data_cpp(secret, secret_len);

  mbedtls_pk_context rsa;
  mbedtls_pk_init(&rsa);
  ret =
      mbedtls_pk_parse_key(&rsa, unsealed.data(), unsealed.size(), nullptr, 0);
  if (ret != 0) {
    LL_CRITICAL("cannot parse secret key: %#x", -ret);
    return -1;
  }

  ret = mbedtls_pk_write_pubkey_pem(&rsa, pubkey, cap_pubkey);
  if (ret != 0) {
    LL_CRITICAL("cannot write pubkey to PEM: %#x", -ret);
    return -ret;
  }

  mbedtls_pk_free(&rsa);
  return 0;
}

mbedtls_pk_context g_rsa_sk;

int provision_rsa_id(const sgx_sealed_data_t *secret, size_t secret_len) {
  int ret;
  try {
    vector<uint8_t> unsealed = _sgx_unseal_data_cpp(secret, secret_len);
    LL_LOG("unsealed secret");

    mbedtls_pk_init(&g_rsa_sk);
    ret = mbedtls_pk_parse_key(&g_rsa_sk, unsealed.data(), unsealed.size(),
                               nullptr, 0);
    if (ret != 0) {
      LL_CRITICAL("cannot parse secret key: %#x", -ret);
      return -1;
    }

    return 0;
  } catch (const std::exception &e) {
    LL_CRITICAL("%s", e.what());
    return -1;
  }
}

int query_rsa_pubkey(unsigned char *pubkey, size_t cap_pubkey) {
  if (0 == mbedtls_pk_can_do(&g_rsa_sk, MBEDTLS_PK_RSA)) {
    LL_CRITICAL("key is not ready");
    return RSA_KEY_NOT_PROVISIONED;
  }

  int ret = mbedtls_pk_write_pubkey_pem(&g_rsa_sk, pubkey, cap_pubkey);
  if (ret != 0) {
    LL_CRITICAL("cannot write pubkey to PEM: %#x", -ret);
    return -ret;
  }

  return 0;
}