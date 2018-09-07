#ifndef ENCLAVE_RPC_H
#define ENCLAVE_RPC_H

#include "enclave-rpc-server.h"
#include <jsonrpccpp/server/connectors/httpserver.h>

#include <string>
#include <sgx_urts.h>

using namespace std;

class EnclaveRPC : public exch::rpc::AbsServer {
 private:
  sgx_enclave_id_t eid;

 public:
    EnclaveRPC(sgx_enclave_id_t eid, jsonrpc::AbstractServerConnector &conn);
    bool appendBlock2FIFO(const std::string &block_header) override;
    bool deposit(const Json::Value &merkle_proof, const string &public_key) override;
    bool distributeSettlementPkg(const std::string& param1) override;
    bool ackSettlementPkg(const std::string& param1) override;

    bool ethSendOrder(const std::string &order) override;
    bool ethWithdraw(const std::string &withdraw) override;
    bool ethSendProof(const std::string &proof) override;
    bool ethSendHeader(const std::string &header) override;

};

#endif /* ifndef ENCLAVE_RPC_H */
