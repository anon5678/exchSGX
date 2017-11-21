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

#include "../common/ssl_context.h"

using std::string;
using std::vector;

#if defined(MBEDTLS_SSL_CACHE_C)
#include "mbedtls/ssl_cache.h"
#endif

#if defined(MBEDTLS_MEMORY_BUFFER_ALLOC_C)
#include "mbedtls/memory_buffer_alloc.h"
#endif

#define HTTP_RESPONSE \
    "HTTP/1.0 200 OK\r\nContent-Type: text/html\r\n\r\n" \
    "<h2>mbed TLS Test Server</h2>\r\n" \
    "<p>Successful connection using: %s</p>\r\n"

class SSLServerContext {
 private:
  /*
   * static members
   */
  const static string pers;
  static sgx_thread_mutex_t mutex;

  /*
   * global server state
   */
  mbedtls_entropy_context entropy;
  mbedtls_ctr_drbg_context ctr_drbg;
  mbedtls_ssl_config conf;
  mbedtls_x509_crt srvcert;
  mbedtls_x509_crt cachain;
  mbedtls_pk_context* priv_key;

  /*
   * error message buffer
   */
  char error_msg[1024];

  /*
   * configuration
   */
  static int debug_level;

  /*
   * debug callback
   */
  static void mydebug(void *ctx, int level, const char *file, int line, const char *str);

 public:
  SSLServerContext();

  // disable copy and move
  SSLServerContext(const SSLServerContext &) = delete;
  SSLServerContext(SSLServerContext &&) = delete;
  SSLServerContext &operator=(const SSLServerContext &) = delete;
  SSLServerContext &operator=(SSLServerContext &&)= delete;

  ~SSLServerContext();
  void handle(long int thread_id, thread_info_t *);
  string getError(int errno);
};

#endif //MBEDTLS_SGX_SSL_SERVER_THREAD_H
