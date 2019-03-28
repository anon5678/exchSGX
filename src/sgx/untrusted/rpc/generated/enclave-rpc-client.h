/**
 * This file is generated by jsonrpcstub, DO NOT CHANGE IT MANUALLY!
 */

#ifndef JSONRPC_CPP_STUB_EXCH_RPC_ABSCLIENT_H_
#define JSONRPC_CPP_STUB_EXCH_RPC_ABSCLIENT_H_

#include <jsonrpccpp/client.h>

namespace exch {
    namespace rpc {
        class AbsClient : public jsonrpc::Client
        {
            public:
                AbsClient(jsonrpc::IClientConnector &conn, jsonrpc::clientVersion_t type = jsonrpc::JSONRPC_CLIENT_V2) : jsonrpc::Client(conn, type) {}

                bool appendBlock2FIFO(const std::string& param01) 
                {
                    Json::Value p;
                    p.append(param01);
                    Json::Value result = this->CallMethod("appendBlock2FIFO",p);
                    if (result.isBool())
                        return result.asBool();
                    else
                        throw jsonrpc::JsonRpcException(jsonrpc::Errors::ERROR_CLIENT_INVALID_RESPONSE, result.toStyledString());
                }
                bool deposit(const Json::Value& param01, const std::string& param02) 
                {
                    Json::Value p;
                    p.append(param01);
                    p.append(param02);
                    Json::Value result = this->CallMethod("deposit",p);
                    if (result.isBool())
                        return result.asBool();
                    else
                        throw jsonrpc::JsonRpcException(jsonrpc::Errors::ERROR_CLIENT_INVALID_RESPONSE, result.toStyledString());
                }
                bool distributeSettlementPkg(const std::string& param01) 
                {
                    Json::Value p;
                    p.append(param01);
                    Json::Value result = this->CallMethod("distributeSettlementPkg",p);
                    if (result.isBool())
                        return result.asBool();
                    else
                        throw jsonrpc::JsonRpcException(jsonrpc::Errors::ERROR_CLIENT_INVALID_RESPONSE, result.toStyledString());
                }
                bool ackSettlementPkg(const std::string& param01) 
                {
                    Json::Value p;
                    p.append(param01);
                    Json::Value result = this->CallMethod("ackSettlementPkg",p);
                    if (result.isBool())
                        return result.asBool();
                    else
                        throw jsonrpc::JsonRpcException(jsonrpc::Errors::ERROR_CLIENT_INVALID_RESPONSE, result.toStyledString());
                }
        };

    }
}
#endif //JSONRPC_CPP_STUB_EXCH_RPC_ABSCLIENT_H_
