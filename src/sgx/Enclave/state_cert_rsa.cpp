#include <sgx_tseal.h>
#include <stdexcept>
#include <cstring>
#include <string>
#include <vector>

#include "state.h"
#include "utils.h"

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
  auto sealed_secret = (const sgx_sealed_data_t *) secret_key;
  int ret;
  try {
    vector<uint8_t> unsealed = utils::sgx_unseal_data_cpp(sealed_secret, secret_key_len);
    LL_LOG("unsealed secret");

    State &s = State::getInstance();

    ret = mbedtls_pk_parse_key(&s.fairnessServerKey, unsealed.data(), unsealed.size(), nullptr, 0);
    if (ret != 0) {
      LL_CRITICAL("cannot parse secret key: %#x", -ret);
      return -1;
    }

    // copy the certificate in PEM format
    s.fairnessServerCertPEM.clear();
    s.fairnessServerCertPEM += cert_pem;

    LL_LOG("key provisioned");

    // PEM length includes the terminating null
    if (s.fairnessServerCertPEM.back() != '\0')
      s.fairnessServerCertPEM += '\0';

    return 0;
  } catch (const std::exception &e) {
    LL_CRITICAL("%s", e.what());
    return -1;
  }
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
  if (0 == mbedtls_pk_can_do(&s.fairnessServerKey, MBEDTLS_PK_RSA)) {
    LL_CRITICAL("key is not ready");
    return RSA_KEY_NOT_PROVISIONED;
  }

  int ret = mbedtls_pk_write_pubkey_pem(&s.fairnessServerKey, o_pubkey, cap_pubkey);
  if (ret != 0) {
    LL_CRITICAL("cannot write pubkey to PEM: %#x", -ret);
    return -ret;
  }

  if (s.fairnessServerCertPEM.empty()) {
    LL_CRITICAL("cert is not provisioned");
  } else {
    strncpy(o_cert_pem, s.fairnessServerCertPEM.c_str(), cap_cert_pem);
  }

  return 0;
}
