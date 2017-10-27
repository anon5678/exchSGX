#include "state.h"


#include "log.h"
#include "../common/ssl_context.h"
#include "Enclave_t.h"
#include "tls_server_threaded.h"

#include <mbedtls/net_v.h>

using namespace exch::enclave;

int ssl_conn_init(void) {
  try {
    state::connectionHandler = new TLSConnectionHandler();
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
  state::connectionHandler->handle(thread_id, thread_info);
}

void ssl_conn_teardown(void) {
  delete state::connectionHandler;
}

int ssl_client_init(const char* hostname, unsigned int port) {
  LL_LOG("connecting to %s:%d", hostname, port);

  try {
    state::tlsClient = new TLSClient(hostname, port);
    state::tlsClient->Connect();

    return 0;
  }
  catch (const std::exception& e) {
    LL_CRITICAL("tls client error: %s", e.what());
  }
  catch (...) {
    LL_CRITICAL("something stupid");
  }

  return -1;
}

int ssl_client_write_test() {
  vector<uint8_t> dummy {1,2,3,4};
  state::tlsClient->Send(dummy);
  return 0;
}

void ssl_client_teardown() {
  delete state::tlsClient;
}