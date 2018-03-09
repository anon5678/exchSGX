#ifndef MBEDTLS_SGX_SSL_CONTEXT_H
#define MBEDTLS_SGX_SSL_CONTEXT_H

#include "mbedtls/ssl.h"
#include "mbedtls/net_v.h"

typedef struct {
  mbedtls_net_context client_fd;
  int thread_complete;
  // TODO: seems like we can remove config?
  const mbedtls_ssl_config *config;
} ssl_context;

#endif //MBEDTLS_SGX_SSL_CONTEXT_H
