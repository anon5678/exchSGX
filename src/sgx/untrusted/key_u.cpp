#include "key_u.h"

#include <sgx.h>
#include <sgx_eid.h>
#include <sgx_error.h>
#include <sgx_tseal.h>

#include <iostream>
#include <string>
#include <exception>

#include "Enclave_u.h"
#include "../common/errno.h"
#include "../common/base64.hxx"

using std::string;
using std::cout;
using std::endl;
using namespace std;

/*!
 * unseal the secret signing and return the corresponding address
 * @param[in] eid
 * @param[in] sealed_key
 * @return a string of corresponding address
 */
string unseal_key(sgx_enclave_id_t eid, const string &sealed_key, exch::keyUtils::KeyType key_type) {
  unsigned char secret_sealed[SECRETKEY_SEALED_LEN];
  unsigned char pubkey[PUBKEY_LEN];

  size_t buffer_used = (size_t) ext::b64_pton(sealed_key.c_str(), secret_sealed,
                                             sizeof secret_sealed);

  int ret = 0;
  sgx_status_t ecall_ret;
  ecall_ret = unseal_secret_and_leak_public_key(
      eid, &ret, reinterpret_cast<sgx_sealed_data_t*>(secret_sealed),
      buffer_used, pubkey);
  if (ecall_ret != SGX_SUCCESS || ret != 0) {
    throw runtime_error("ecdsa_keygen_unseal failed with " + to_string(ret));
  }
  switch (key_type) {
    case exch::keyUtils::HYBRID_ENCRYPTION_KEY:
      return ext::b64_encode(pubkey, sizeof pubkey);
    default:
      throw std::runtime_error("unknown key type");
  }
}

void provision_key(sgx_enclave_id_t eid, const string& sealed_key, exch::keyUtils::KeyType type) {
  unsigned char _sealed_key_buf[SECRETKEY_SEALED_LEN];
  auto buffer_used = (size_t)ext::b64_pton(sealed_key.c_str(), _sealed_key_buf, sizeof _sealed_key_buf);

  int ret = 0;
  sgx_status_t ecall_ret;

  switch (type) {
    case exch::keyUtils::HYBRID_ENCRYPTION_KEY:
      ecall_ret = provision_hybrid_key(eid, &ret,
                                       reinterpret_cast<sgx_sealed_data_t*>(_sealed_key_buf), buffer_used);
      break;
    default:
      cerr << "unknown key type" << endl;
      ecall_ret = SGX_ERROR_UNEXPECTED;
      ret = -1;
  }

  if (ecall_ret != SGX_SUCCESS || ret != 0) {
    throw std::runtime_error("tc_provision_key returns " + to_string(ret));
  }
}
