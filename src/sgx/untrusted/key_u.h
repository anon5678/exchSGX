#ifndef SRC_APP_KEY_UTILS_H_
#define SRC_APP_KEY_UTILS_H_

#include <sgx_eid.h>
#include <string>

using std::string;

namespace exch {
namespace keyUtils {
enum KeyType {
  HYBRID_ENCRYPTION_KEY
};
}
}

string unseal_key(sgx_enclave_id_t eid, const string &sealed_key, exch::keyUtils::KeyType key_type);
void provision_key(sgx_enclave_id_t eid, const string &sealed_key, exch::keyUtils::KeyType);

#endif  // SRC_APP_KEY_UTILS_H_
