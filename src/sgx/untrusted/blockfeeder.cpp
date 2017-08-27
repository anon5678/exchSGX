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

bool push_one(sgx_enclave_id_t eid, bitcoindRPCClient &rpc, int blocknum) {
  try {
    string hdr_hex = get_blockheader_hex(rpc, blocknum);
    push(eid, hdr_hex.c_str());
    return true;
  }
  catch (const jsonrpc::JsonRpcException &e) {
    cerr << "JSONRPC error: " << e.what();
  }
  catch (const exception &e) {
    cerr << "std exception catched: " << e.what() << endl;
  }
  catch (...) {
    cerr << "unknown err" << endl;
  }

  return false;
}

int main() {
  // note that bitcoin uses JSON-RPC 1.0
  jsonrpc::HttpClient connector(::cfg::bitcoind_rpc_addr);
  bitcoindRPCClient rpc(connector, jsonrpc::JSONRPC_CLIENT_V1);

  sgx_enclave_id_t eid;

  if (0 != initialize_enclave(&eid)) {
    cerr << "failed to init enclave" << endl;
    exit(-1);
  }

  int test_block_1[3] {10000, 10001, 10002};
  int test_block_2[4] {10003, 10004, 10005, 10007};


  cout << "Testing one. Suppose to succeed\n";
  cout << "===============================" << endl;

  for (auto b : test_block_1) {
    push_one(eid, rpc, b);
  }

  cout << endl;
  cout << "Testing two. Suppose to fail on the last one\n";
  cout << "============================================" << endl;

  for (auto b : test_block_2) {
    push_one(eid, rpc, b);
  }

  return 0;
}

