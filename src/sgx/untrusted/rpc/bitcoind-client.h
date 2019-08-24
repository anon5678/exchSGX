#include "generated/bitcoind-rpc-client.h"

#include <sstream>
#include <string>
#include <iostream>

#include <json/json.h>
#include <json/reader.h>
#include <json/value.h>

#include <jsonrpccpp/client.h>
#include <jsonrpccpp/client/connectors/httpclient.h>

#include <boost/format.hpp>

using namespace std;
using Json::Reader;
using Json::Value;
using jsonrpc::Errors;

#include <log4cxx/logger.h>

using log4cxx::LoggerPtr;

class Bitcoind
{
 private:
  jsonrpc::HttpClient connector;
  bitcoindRPCClient bitcoind_stub;

 public:
  explicit Bitcoind(
      const string &hostname = "localhost",
      int port = 8332,
      const string &auth = "exch:goodpass")
      : connector(
            "http://" + auth + "@" + hostname + ":" + std::to_string(port)),
        bitcoind_stub(connector, jsonrpc::JSONRPC_CLIENT_V1)
  {
  }

  int getblockcount();
  string getblockhash(int block_height) noexcept(false);
  string getblockheader(const string &block_hash, bool format = false);
  Value getblock(const string &block_hash);
  Value getrawtransaction(const string &tx_hash, bool JSONformat);
  void sendrawtransaction(const string &tx_hex);
  void generatetoaddress(int nblocks, const string &tx_hash);
};

class BitcoindRPCException : public std::exception
{ /**
   * Based on bitcoin-api-cpp
   * original author: Krzysztof Okupski
   */
  static std::pair<int, string> gen_error_code(
      int errcode, const std::string &message)
  {
    int code;
    string msg;

    /* Connection error */
    if (errcode == Errors::ERROR_CLIENT_CONNECTOR) {
      code = errcode;
      msg = removePrefix(message, " -> ");
      /* Authentication error */
    } else if (
        errcode == Errors::ERROR_RPC_INTERNAL_ERROR && message.size() == 18) {
      code = errcode;
      msg = "Failed to authenticate successfully";
      /* Miscellaneous error */
    } else {
      code = parseCode(message);
      msg = parseMessage(message);
      if (msg == "Transaction already in block chain") {
          code = 0;
      }
    }

    return std::make_pair(code, msg);
  }

  static std::string removePrefix(
      const std::string &in, const std::string &pattern)
  {
    std::string ret = in;

    size_t pos = ret.find(pattern);

    if (pos <= ret.size()) {
      ret.erase(0, pos + pattern.size());
    }

    return ret;
  }

  static int parseCode(const std::string &in)
  {
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

  static std::string parseMessage(const std::string &in)
  {
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

 private:
  std::runtime_error m_except;
  int error;

 public:
  explicit BitcoindRPCException(int errcode, const std::string &message)
      : error(gen_error_code(errcode, message).first), m_except(gen_error_code(errcode, message).second)
  {
  }

  const int getCode() {
      return error;
  }

  const char *what() const noexcept { 
      return m_except.what(); }
};
