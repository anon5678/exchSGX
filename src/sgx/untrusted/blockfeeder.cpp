//
// Created by fanz on 7/11/17.
//

#include "bitcoindrpcclient.h"
#include "jsonrpccpp/client/connectors/httpclient.h"

#include <iostream>
#include <string>
#include <jsonrpccpp/common/exception.h>
#include <string>
#include <json/json.h>

using namespace std;

#define HDR_FMT_JSON  true
#define HDR_FMT_BIN   false

namespace cfg {
string bitcoind_rpc_addr = "http://exch:goodpass@localhost:8332";
}

int main() {
  jsonrpc::HttpClient connector(::cfg::bitcoind_rpc_addr);

  // note that Bitcoin uses JSON-RPC 1.0
  bitcoindRPCClient rpcClient(connector, jsonrpc::JSONRPC_CLIENT_V1);

  try {
    int block_count = rpcClient.getblockcount();
    cout << block_count << " blocks discovered" << endl;

    string hash = rpcClient.getblockhash(block_count);

    cout << block_count << " => " << hash << endl;

    Json::Value block_header = rpcClient.getblockheader(hash, HDR_FMT_BIN);
    cout << block_header.asString() << endl;

    block_header = rpcClient.getblockheader(hash, HDR_FMT_JSON);
    cout << block_header.toStyledString() << endl;

  }
  catch (const jsonrpc::JsonRpcException& e) {
    cerr << "Error code is: " << e.GetCode() << endl;
  }
  catch (const exception& e) {
    cerr << e.what() << endl;
  }

  return 0;
}

