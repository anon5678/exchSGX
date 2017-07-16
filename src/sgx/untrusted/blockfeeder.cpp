//
// Created by fanz on 7/11/17.
//

#include "bitcoindrpcclient.h"
#include "Enclave_u.h"
#include "jsonrpccpp/client/connectors/httpclient.h"
#include "Utils.h"

#include <iostream>
#include <string>
#include <jsonrpccpp/common/exception.h>
#include <string>
#include <json/json.h>

#include <memory>

using namespace std;

namespace cfg {
string bitcoind_rpc_addr = "http://exch:goodpass@localhost:8332";
}

string get_blockheader_hex(bitcoindRPCClient &rpc, uint32_t height) {
  string hash = rpc.getblockhash(height);
  Json::Value hdr = rpc.getblockheader(hash, false); // false for binary format
  return hdr.asString();
}

int main() {
  // note that Bitcoin uses JSON-RPC 1.0
  jsonrpc::HttpClient connector(::cfg::bitcoind_rpc_addr);
  bitcoindRPCClient rpc(connector, jsonrpc::JSONRPC_CLIENT_V1);

  sgx_enclave_id_t eid;

  if (0 != initialize_enclave(&eid)) {
    cerr << "failed to init enclave" << endl;
    exit(-1);
  }

  try {
    string hdr_hex = get_blockheader_hex(rpc, 10000);
    push(eid, hdr_hex.c_str());
  }
  catch (const jsonrpc::JsonRpcException &e) {
    cerr << e.what() << endl;
  }
  catch (const exception &e) {
    cerr << "std exception catched: " << e.what() << endl;
  }
  return 0;
}

