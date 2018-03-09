#ifndef PROJECT_ENCLAVE_TLS_H
#define PROJECT_ENCLAVE_TLS_H

#include "utils.h"

#include "mbedtls/pk.h"
#include <string>
#include <mbedtls/pk.h>

namespace exch {
namespace enclave {
namespace tls {

struct TLSCert {
  bytes cert;
  mbedtls_pk_context sk;

  TLSCert() {
    mbedtls_pk_init(&sk);
  }
  ~TLSCert() {
    mbedtls_pk_free(&sk);
  }

  const bytes& getCert() const { return cert; }
  const mbedtls_pk_context *getSkPtr() const { return &sk; }
};

}
}
}
#endif //PROJECT_ENCLAVE_TLS_H
