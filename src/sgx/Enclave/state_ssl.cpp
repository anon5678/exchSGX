#include "state.h"

using namespace exch::enclave;

int fairness_tls_server_init(void) {
  try {
    state::fairnessServerTrustedPart = new SSLContextManager();
  }
  catch (const std::exception &e) {
    LL_CRITICAL("cannot init tls: %s", e.what());
    return -1;
  }
  catch (...) {
    LL_CRITICAL("cannot init tls: %s", "unknown error");
    return -1;
  }

  return 0;
}

void fairness_tls_server_tcp_conn_handler(long int thread_id, thread_info_t *thread_info) {
  LL_LOG("delegating socket %d to handler", thread_info->client_fd.fd);
  state::fairnessServerTrustedPart->handle(thread_id, thread_info);
}

void fairness_tls_server_free(void) {
  delete state::fairnessServerTrustedPart;
}

int client_facing_tls_server_init(void) {
  try {
    state::clientTLSServerTrustedPart = new SSLContextManager();
  }
  catch (const std::exception &e) {
    LL_CRITICAL("cannot init tls: %s", e.what());
    return -1;
  }
  catch (...) {
    LL_CRITICAL("cannot init tls: %s", "unknown error");
    return -1;
  }

  return 0;
}

void client_facing_tls_server_tcp_conn_handler(long int thread_id, thread_info_t *thread_info) {
  LL_LOG("serving socket %d", thread_info->client_fd.fd);
  state::clientTLSServerTrustedPart->handle(thread_id, thread_info);
}


void client_facing_tls_server_free(void) {
  delete state::clientTLSServerTrustedPart;
}

int ssl_client_init(const char *hostname, unsigned int port) {
  LL_LOG("connecting to %s:%d", hostname, port);

  try {
    state::tlsClient = new TLSClient(hostname, port);
    state::tlsClient->Connect();

    return 0;
  }
  catch (const std::exception &e) {
    LL_CRITICAL("tls client error: %s", e.what());
  }
  catch (...) {
    LL_CRITICAL("something stupid");
  }

  return -1;
}

int ssl_client_write_test() {
  vector<uint8_t> dummy{1, 2, 3, 4};
  vector<uint8_t> out;

  try {
    state::tlsClient->SendWaitRecv(dummy, out);
  }
  catch (const std::exception &e) {
    LL_CRITICAL("exception: %s", e.what());
    return -1;
  }

  hexdump("got from server: ", out.data(), out.size());
  // state::tlsClient->SendWaitRecv(dummy, out);
  return 0;
}

void ssl_client_teardown() {
  delete state::tlsClient;
}