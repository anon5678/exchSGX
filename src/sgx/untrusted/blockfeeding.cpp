//
// Created by fanz on 8/28/17.
//

#include "blockfeeding.h"
#include "bitcoindrpcclient.h"
#include "Enclave_u.h"
#include "jsonrpccpp/client/connectors/httpclient.h"

#include <string>
#include <iostream>

using namespace std;

namespace cfg {
string bitcoind_rpc_addr = "http://exch:goodpass@localhost:8332";
}

extern sgx_enclave_id_t eid;

bool tryAddBlock(sgx_enclave_id_t eid, bitcoindRPCClient &rpc, int blocknum) {
  try {
    string hash = rpc.getblockhash(blocknum);
    Json::Value block_header = rpc.getblockheader(hash, false);
    appendBlockToFIFO(eid, block_header.asCString());
    return true;
  }
  catch (const jsonrpc::JsonRpcException &e) {
    cerr << "JSONRPC error: " << e.what();
  }
  catch (const exception &e) {
    cerr << "std exception: " << e.what() << endl;
  }
  return false;
}

int test_feed_blocks() {
  // note that bitcoin uses JSON-RPC 1.0
  jsonrpc::HttpClient connector(::cfg::bitcoind_rpc_addr);
  bitcoindRPCClient rpc(connector, jsonrpc::JSONRPC_CLIENT_V1);

  int test_block_1[3] {10000, 10001, 10002};
  int test_block_2[4] {10003, 10004, 10005, 10007};


  cout << "Testing one. Suppose to succeed\n";
  cout << "===============================" << endl;

  for (auto b : test_block_1) {
    tryAddBlock(eid, rpc, b);
  }

  cout << endl;
  cout << "Testing two. Suppose to fail on the last one\n";
  cout << "============================================" << endl;

  for (auto b : test_block_2) {
    tryAddBlock(eid, rpc, b);
  }

  return 0;
}