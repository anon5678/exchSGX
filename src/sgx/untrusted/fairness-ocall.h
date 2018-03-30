#ifndef TESSERACT_ENCLAVE_RPC_CLIENT_IMPL_H
#define TESSERACT_ENCLAVE_RPC_CLIENT_IMPL_H

#include "enclave-rpc-client.h"
#include <jsonrpccpp/client/connectors/httpclient.h>

#include <iostream>

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
    std::cout << "connect to " << hostname << std::endl;
    connector = new HttpClient(hostname);
    client = new exch::rpc::AbsClient(*connector);
  }
  ~Client() {
    delete client;
  }

  // leader -> followers
  // called by sendMessagesToFairnessFollower
  void distributeSettlementPkg(const string& msg) {
    client->distributeSettlementPkg(msg);
  }

  // follower -> leader
  // called by sendAckToFairnessLeader
  void ackSettlementPkg(const string& msg) {
    client->ackSettlementPkg(msg);
  }
};

}
}

#endif //TESSERACT_ENCLAVE_RPC_CLIENT_IMPL_H
