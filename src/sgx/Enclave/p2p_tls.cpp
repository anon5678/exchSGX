//
// Created by fanz on 8/27/17.
//

#include "p2p_tls.h"
#include "tls_client.h"
#include "log.h"

int test_tls_client(const char* hostname, unsigned int port) {
  LL_LOG("connecting to %s:%d", hostname, port);

  try {
    TLSClient tlsClient(hostname, port);
    tlsClient.Connect();

    vector<uint8_t> dummy {1,2,3,4};
    tlsClient.Send(dummy);
  }
  catch (const std::exception& e) {
    LL_CRITICAL("tls client error: %s", e.what());
  }
  catch (...) {
    LL_CRITICAL("something stupid");
  }

  return 0;
}
