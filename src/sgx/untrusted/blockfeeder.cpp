//
// Created by fanz on 7/11/17.
//

#include "bitcoindrpcclient.h"
#include "jsonrpccpp/client/connectors/httpclient.h"

#include <iostream>
#include <string>

using namespace std;

namespace cfg {
string bitcoind_rpc_addr = "http://exch:goodpass@localhost:8332";
}

int main() {
  jsonrpc::HttpClient connector(::cfg::bitcoind_rpc_addr);
  bitcoindRPCClient rpcClient(connector, jsonrpc::JSONRPC_CLIENT_V1);

  try {
    int block_count = rpcClient.getblockcount();
    cout << block_count << " blocks discovered" << endl;
  }
  catch (const exception& e) {
    cerr << e.what() << endl;
  }

  return 0;
}

