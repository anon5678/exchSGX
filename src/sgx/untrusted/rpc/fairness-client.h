#ifndef TESSERACT_ENCLAVE_RPC_CLIENT_IMPL_H
#define TESSERACT_ENCLAVE_RPC_CLIENT_IMPL_H

#include <jsonrpccpp/client/connectors/httpclient.h>
#include "generated/enclave-rpc-client.h"

#include <iostream>
#include <memory>

namespace exch
{
namespace rpc
{
using namespace jsonrpc;
using namespace std;

class Client
{
 private:
  HttpClient connector;
  std::unique_ptr<exch::rpc::AbsClient> client;

 public:
  Client(const string &host, uint16_t port)
      : connector("http://" + host + ":" + to_string(port))
  {
    client = std::unique_ptr<exch::rpc::AbsClient>(
        new exch::rpc::AbsClient(connector));
  }
  ~Client() {}

  // leader -> followers
  // called by sendMessagesToFairnessFollower
  void distributeSettlementPkg(const string &msg)
  {
    client->distributeSettlementPkg(msg);
  }

  // follower -> leader
  // called by sendAckToFairnessLeader
  void ackSettlementPkg(const string &msg) { client->ackSettlementPkg(msg); }
};

}  // namespace rpc
}  // namespace exch

#endif  // TESSERACT_ENCLAVE_RPC_CLIENT_IMPL_H
