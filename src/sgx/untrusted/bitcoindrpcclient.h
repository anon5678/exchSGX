/**
 * This file is generated by jsonrpcstub, DO NOT CHANGE IT MANUALLY!
 */

#ifndef JSONRPC_CPP_STUB_BITCOINDRPCCLIENT_H_
#define JSONRPC_CPP_STUB_BITCOINDRPCCLIENT_H_

#include <jsonrpccpp/client.h>

class bitcoindRPCClient : public jsonrpc::Client
{
    public:
        bitcoindRPCClient(jsonrpc::IClientConnector &conn, jsonrpc::clientVersion_t type = jsonrpc::JSONRPC_CLIENT_V2) : jsonrpc::Client(conn, type) {}

        int getblockcount() throw (jsonrpc::JsonRpcException)
        {
            Json::Value p;
            p = Json::nullValue;
            Json::Value result = this->CallMethod("getblockcount",p);
            if (result.isInt())
                return result.asInt();
            else
                throw jsonrpc::JsonRpcException(jsonrpc::Errors::ERROR_CLIENT_INVALID_RESPONSE, result.toStyledString());
        }
        std::string getblockhash(int param1) throw (jsonrpc::JsonRpcException)
        {
            Json::Value p;
            p.append(param1);
            Json::Value result = this->CallMethod("getblockhash",p);
            if (result.isString())
                return result.asString();
            else
                throw jsonrpc::JsonRpcException(jsonrpc::Errors::ERROR_CLIENT_INVALID_RESPONSE, result.toStyledString());
        }
};

#endif //JSONRPC_CPP_STUB_BITCOINDRPCCLIENT_H_
