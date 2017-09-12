#ifndef ENCLAVE_RPC_H
#define ENCLAVE_RPC_H

#include "abstractenclaverpc.h"
#include <jsonrpccpp/server/connectors/httpserver.h>

#include <string>
#include <sgx_urts.h>


class EnclaveRPC: public AbstractEnclaveRPC {
    private:
        sgx_enclave_id_t eid;

    public:
        EnclaveRPC(sgx_enclave_id_t eid, jsonrpc::AbstractServerConnector& conn);

        virtual bool appendBlock2FIFO(const std::string& block_header);
};

#endif /* ifndef ENCLAVE_RPC_H */
