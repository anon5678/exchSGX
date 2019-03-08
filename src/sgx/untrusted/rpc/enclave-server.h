#ifndef ENCLAVE_RPC_H
#define ENCLAVE_RPC_H

#include <jsonrpccpp/server/connectors/httpserver.h>
#include "generated/enclave-rpc-server.h"

#include <sgx_urts.h>
#include <string>

using namespace std;

class EnclaveRPC : public exch::rpc::AbsServer
{
 private:
  sgx_enclave_id_t eid;

 public:
  EnclaveRPC(sgx_enclave_id_t eid, jsonrpc::AbstractServerConnector &conn);
  bool appendBlock2FIFO(const std::string &block_header) override;
  bool deposit(
      const Json::Value &merkle_proof, const string &public_key) override;
  bool distributeSettlementPkg(const std::string &param1) override;
  bool ackSettlementPkg(const std::string &param1) override;
};

#endif /* ifndef ENCLAVE_RPC_H */
