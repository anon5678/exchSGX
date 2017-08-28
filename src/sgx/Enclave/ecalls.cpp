#include <mbedtls/net_v.h>
#include "Enclave_t.h"
#include "log.h"
#include "tls_server_threaded.h"
#include "../common/ssl_context.h"

TLSConnectionHandler* connectionHandler;

void ssl_conn_init(void) {
  connectionHandler = new TLSConnectionHandler();
}

void ssl_conn_handle(long int thread_id, thread_info_t* thread_info) {
  LL_LOG("delegating socket %d to handler", thread_info->client_fd.fd);
  connectionHandler->handle(thread_id, thread_info);
}

void ssl_conn_teardown(void) {
  delete connectionHandler;
}