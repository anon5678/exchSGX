#include <mbedtls/net_v.h>
#include "Enclave_t.h"
#include "log.h"
#include "tls_server_threaded.h"
#include "../common/ssl_context.h"

TLSConnectionHandler* connectionHandler;

int ssl_conn_init(void) {
  try {
    connectionHandler = new TLSConnectionHandler();
  }
  catch (const std::exception& e) {
    LL_CRITICAL("cannot init tls: %s", e.what());
    return -1;
  }
  catch (...) {
    LL_CRITICAL("cannot init tls: %s", "unknown error");
    return -1;
  }

  return 0;
}

void ssl_conn_handle(long int thread_id, thread_info_t* thread_info) {
  LL_LOG("delegating socket %d to handler", thread_info->client_fd.fd);
  connectionHandler->handle(thread_id, thread_info);
}

void ssl_conn_teardown(void) {
  delete connectionHandler;
}