#include <sgx_tseal.h>
#include <stdexcept>
#include <cstring>
#include <string>
#include <vector>

#include "state.h"

#include "../common/errno.h"

using namespace std;

/*!
 * Called by untrusted. Update the state with provisioned secret_key and cert_pem
 * @param secret_key : sealed secret key
 * @param secret_key_len : length of the sealed secret key
 * @param cert_pem : certificate in PEM format
 * @return 0 on success
 */
int provision_rsa_id(const unsigned char *secret_key, size_t secret_key_len, const char *cert_pem) {
  State &s = State::getInstance();

  return
      s.setCert(CLIENT_FACING, secret_key, secret_key_len, cert_pem) ||
          s.setCert(FAIRNESS, secret_key, secret_key_len, cert_pem);
}

int State::setCert(CertType type, const unsigned char *secret_key, size_t secret_key_len, const char *cert_pem) {
  auto sealed_secret = (const sgx_sealed_data_t *) secret_key;
  int ret;
  try {
    bytes unsealed = utils::sgx_unseal_data_cpp(sealed_secret, secret_key_len);
    LL_LOG("unsealed secret");

    mbedtls_pk_context *sk = nullptr;
    bytes *cert = nullptr;
    switch (type) {
      case CLIENT_FACING:
        sk = &this->clientFacingCert.sk;
        cert = &clientFacingCert.cert;
        break;
      case FAIRNESS:
        sk = &this->fairnessCert.sk;
        cert = &fairnessCert.cert;
        break;
    }

    ret = mbedtls_pk_parse_key(sk, unsealed.data(), unsealed.size(), nullptr, 0);
    if (ret != 0) {
      LL_CRITICAL("cannot parse secret key: %#x", -ret);
      return -1;
    }

    // PEM length includes the terminating null
    string cert_pem_str(cert_pem);
    if (cert_pem_str.back() != '\0')
      cert_pem_str += '\n';

    cert->insert(cert->end(), cert_pem_str.begin(), cert_pem_str.end());

    LL_LOG("key provisioned");

    return 0;
  } catch (const std::exception &e) {
    LL_CRITICAL("%s", e.what());
    return -1;
  }

  return -1;
}

/*!
 * output the pubkey in use
 * @param o_pubkey
 * @param cap_pubkey
 * @param o_cert_pem
 * @param cap_cert_pem
 * @return
 */
int query_rsa_pubkey(unsigned char *o_pubkey, size_t cap_pubkey, char *o_cert_pem, size_t cap_cert_pem) {
  State &s = State::getInstance();
  return s.getPubkey(FAIRNESS, o_pubkey, cap_pubkey, o_cert_pem, cap_cert_pem);
}

int State::getPubkey(CertType type, unsigned char *o_pubkey, size_t cap_pubkey, char *o_cert_pem, size_t cap_cert_pem) {
  const mbedtls_pk_context* sk = nullptr;
  const bytes* cert = nullptr;

  switch (type) {
  case FAIRNESS:
    sk = fairnessCert.getSkPtr();
    cert = &fairnessCert.getCert();
    break;
  case CLIENT_FACING:
    sk = clientFacingCert.getSkPtr();
    cert = &clientFacingCert.getCert();
    break;
  }

  if (0 == mbedtls_pk_can_do(sk, MBEDTLS_PK_RSA)) {
    LL_CRITICAL("key is not ready");
    return RSA_KEY_NOT_PROVISIONED;
  }

  // Needing to cast away const is a bug in mbedtls. Hopefully it will be fixed soon.
  int ret = mbedtls_pk_write_pubkey_pem(const_cast<mbedtls_pk_context*>(sk), o_pubkey, cap_pubkey);
  if (ret != 0) {
    LL_CRITICAL("cannot write pubkey to PEM: %#x", -ret);
    return -ret;
  }

  if (cert->empty()) {
    LL_CRITICAL("cert is not provisioned");
    return -1;
  } else {
    strncpy(o_cert_pem, (const char *) cert->data(), cap_cert_pem);
  }

  return 0;
}
