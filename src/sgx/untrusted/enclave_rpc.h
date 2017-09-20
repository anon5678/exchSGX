#ifndef ENCLAVE_RPC_H
#define ENCLAVE_RPC_H

#include "abstractenclaverpc.h"
#include <jsonrpccpp/server/connectors/httpserver.h>

#include <string>
#include <sgx_urts.h>

using namespace std;

class EnclaveRPC : public AbstractEnclaveRPC {
 private:
  sgx_enclave_id_t eid;

 public:
  EnclaveRPC(sgx_enclave_id_t eid, jsonrpc::AbstractServerConnector &conn);
  bool appendBlock2FIFO(const std::string &block_header) override;
  bool deposit(const string &merkle_proof, const string &public_key) override;
};

#endif /* ifndef ENCLAVE_RPC_H */
