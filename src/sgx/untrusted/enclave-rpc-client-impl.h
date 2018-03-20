#ifndef TESSERACT_ENCLAVE_RPC_CLIENT_IMPL_H
#define TESSERACT_ENCLAVE_RPC_CLIENT_IMPL_H

#include "enclave-rpc-client.h"
#include <jsonrpccpp/client/connectors/httpclient.h>

#include <iostream>

using namespace std;

namespace exch {
namespace rpc {

using namespace jsonrpc;
using namespace std;

class Client {
private:
  HttpClient *connector;
  exch::rpc::AbsClient *client;
public:
  Client(const string &host, uint16_t port) {
    string hostname = "http://" + host + ":" + to_string(port);
    connector = new HttpClient(hostname);
    client = new exch::rpc::AbsClient(*connector);
  }
  ~Client() {
    delete client;
  }

  // call by a leader
  void distributeSettlementPkg(const unsigned char *msg, size_t size) {
    client->distributeSettlementPkg(string((char *) msg, size));
  }

  void ackSettlementPkg() {
    // TODO: replace ack with a signature
    client->ackSettlementPkg("ack");
  }
};

}
}

#endif //TESSERACT_ENCLAVE_RPC_CLIENT_IMPL_H
