//
// Created by fanz on 8/27/17.
//

#include "p2p_tls.h"
#include "tls_client.h"

int test_tls_client(const char* hostname, unsigned int port) {
  TLSClient tlsClient(hostname, port);
  tlsClient.Connect();
}
