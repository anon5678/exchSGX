#include "state.h"

using namespace exch::enclave;

int client_facing_tls_server_init(void) {
//  try {
//    state::clientTLSServerTrustedPart = new SSLServerContext(<#initializer#>, <#initializer#>);
//  }
//  catch (const std::exception &e) {
//    LL_CRITICAL("cannot init tls: %s", e.what());
//    return -1;
//  }
//  catch (...) {
//    LL_CRITICAL("cannot init tls: %s", "unknown error");
//    return -1;
//  }
//
  return 0;
}

void client_facing_tls_server_tcp_conn_handler(long int thread_id, ssl_context *thread_info) {
//  LL_LOG("serving socket %d", thread_info->client_fd.fd);
//  state::clientTLSServerTrustedPart->handle(thread_id, thread_info);
}


void client_facing_tls_server_free(void) {
//  delete state::clientTLSServerTrustedPart;
}

