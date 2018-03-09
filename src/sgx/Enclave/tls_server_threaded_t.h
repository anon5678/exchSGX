#ifndef MBEDTLS_SGX_SSL_SERVER_THREAD_H
#define MBEDTLS_SGX_SSL_SERVER_THREAD_H

#define MBEDTLS_CONFIG_FILE "config_client.h"

#if !defined(MBEDTLS_CONFIG_FILE)
#include "mbedtls/config.h"
#else
#include MBEDTLS_CONFIG_FILE
#endif

#if defined(MBEDTLS_PLATFORM_C)
#include "mbedtls/platform.h"
#else
#include <stdio.h>
#define mbedtls_fprintf    fprintf
#define mbedtls_printf     printf
#define mbedtls_snprintf   snprintf
#endif

#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/certs.h"
#include "mbedtls/x509.h"
#include "mbedtls/ssl.h"
#include "mbedtls/net_v.h"
#include "mbedtls/net_f.h"
#include "mbedtls/error.h"

#include <vector>
#include <cstdlib>
#include <cstring>
#include <cstdio>
#include <string>
#include <cstdint>
#include <sgx_thread.h>

#include "utils.h"
#include "tls.h"
#include "../common/ssl_context.h"

using std::string;
using std::vector;

#if defined(MBEDTLS_SSL_CACHE_C)
#include "mbedtls/ssl_cache.h"
#endif

#if defined(MBEDTLS_MEMORY_BUFFER_ALLOC_C)
#include "mbedtls/memory_buffer_alloc.h"
#endif

namespace exch {
namespace enclave {
namespace tls {

struct Session {
  mbedtls_ssl_context* ssl;
  ssl_context* ssl_ctx;
};

class SSLServer {
 private:
  /*
   * static members
   */
  static sgx_thread_mutex_t mutex;

  // server state
  mbedtls_entropy_context entropy;
  mbedtls_ctr_drbg_context ctr_drbg;
  mbedtls_ssl_config conf;
  mbedtls_x509_crt srvcert;
  mbedtls_x509_crt cachain;
  mbedtls_pk_context* priv_key;

  char error_msg[1024];
  static int debug_level;

  // debug callback
  static void mydebug(void *ctx, int level, const char *file, int line, const char *str);

 public:
  SSLServer(const TLSCert &cert);

  // disable copy and move
  SSLServer(const SSLServer &) = delete;
  SSLServer(SSLServer &&) = delete;
  SSLServer &operator=(const SSLServer &) = delete;
  SSLServer &operator=(SSLServer &&)= delete;

  ~SSLServer();
  Session establish(long int thread_id, ssl_context *, bytes &);
  int send(Session session, const bytes&);
  void close(Session &session, bool notify);
  string getError(int errno);
};

}
}
}

#endif //MBEDTLS_SGX_SSL_SERVER_THREAD_H
