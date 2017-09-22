#include "bitcoindrpcclient.h"
#include "jsonrpccpp/client/connectors/httpclient.h"

#include <jsonrpccpp/client.h>
#include <sstream>
#include <string>
#include <string>

#include <jsoncpp/json/json.h>
#include <jsoncpp/json/reader.h>
#include <jsoncpp/json/value.h>
#include <jsonrpccpp/client.h>

using namespace std;
using Json::Value;
using Json::Reader;
using jsonrpc::Errors;

class bitcoinRPC {
  static const string BITCOIND_RPC_ADDR;
  jsonrpc::HttpClient connector;
  bitcoindRPCClient bitcoindClient;

public:
  bitcoinRPC()
      : connector(BITCOIND_RPC_ADDR),
        bitcoindClient(connector, jsonrpc::JSONRPC_CLIENT_V1) {}

  int getblockcount();
  string getblockhash(int block_height);
  string getblockheader(const string &block_hash, bool format);
  Value getblock(const string &block_hash);
  Value getrawtransaction(const string &tx_hash, bool JSONformat);
};

/**
 * Based on bitcoin-api-cpp
 * original author  Krzysztof Okupski
 */

class bitcoinRPCException : public std::exception {
private:
  int code;
  std::string msg;

public:
  explicit bitcoinRPCException(int errcode, const std::string &message) {
    /* Connection error */
    if (errcode == Errors::ERROR_CLIENT_CONNECTOR) {
      this->code = errcode;
      this->msg = removePrefix(message, " -> ");
      /* Authentication error */
    } else if (errcode == Errors::ERROR_RPC_INTERNAL_ERROR &&
               message.size() == 18) {
      this->code = errcode;
      this->msg = "Failed to authenticate successfully";
      /* Miscellaneous error */
    } else {
      this->code = parseCode(message);
      this->msg = parseMessage(message);
    }
  }

  ~bitcoinRPCException() throw(){};

  int getCode() { return code; }


  const char* what() const throw() { return msg.c_str(); }

  std::string removePrefix(const std::string &in, const std::string &pattern) {
    std::string ret = in;

    unsigned int pos = ret.find(pattern);

    if (pos <= ret.size()) {
      ret.erase(0, pos + pattern.size());
    }

    return ret;
  }

  /* Auxiliary JSON parsing */
  int parseCode(const std::string &in) {
    Value root;
    Reader reader;

    /* Remove JSON prefix */
    std::string strJson = removePrefix(in, "INTERNAL_ERROR: : ");
    int ret = -1;

    /* Parse error message */
    bool parsingSuccessful = reader.parse(strJson.c_str(), root);
    if (parsingSuccessful) {
      ret = root["error"]["code"].asInt();
    }

    return ret;
  }

  std::string parseMessage(const std::string &in) {
    Value root;
    Reader reader;

    /* Remove JSON prefix */
    std::string strJson = removePrefix(in, "INTERNAL_ERROR: : ");
    std::string ret = "Error during parsing of >>" + strJson + "<<";

    /* Parse error message */
    bool parsingSuccessful = reader.parse(strJson.c_str(), root);
    if (parsingSuccessful) {
      ret = removePrefix(root["error"]["message"].asString(), "Error: ");
      ret[0] = toupper(ret[0]);
    }

    return ret;
  }
};
