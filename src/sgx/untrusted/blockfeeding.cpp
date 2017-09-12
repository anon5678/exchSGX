#include "blockfeeding.h"
#include "Enclave_u.h"
#include "rpc.h"

#include <algorithm>
#include <iostream>
#include <string>

using namespace std;

extern sgx_enclave_id_t eid;

bool tryAddBlock(sgx_enclave_id_t eid, bitcoinRPC &btc, int blocknum) {
  try {
    string hash = btc.getblockhash(blocknum);
    Json::Value block_header = btc.getblockheader(hash, false);
    int ret;
    ecall_append_block_to_fifo(eid, &ret, block_header.asCString());
    return true;
  } catch (const bitcoinRPCException &e) {
    cerr << "std exception: " << e.what() << endl;
  }
  return false;
}

#include <vector>
#include "merkpath/merkpath.h"

int test_merkle_proof() {
  testMerk(); //return 0;
  bitcoinRPC rpc;

  // testing. Will be removed later
  int test_block = rpc.getblockcount() - 5;
  string block_hash = rpc.getblockhash(test_block);
  Json::Value block_raw = rpc.getblock(block_hash);
  vector<string> txns;
  if (block_raw.isMember("tx")) {
    for (auto itr : block_raw["tx"]) {
      txns.push_back(itr.asString());
    }
  }

  Json::Value txn = rpc.getrawtransaction(txns[55], true);

  // delete up to this point
  string txid = txn["hash"].asString();

  try {

    if (!txn.isMember("blockhash")) {
      throw runtime_error("invalid txn");
    }

    block_hash = txn["blockhash"].asString();
    Json::Value block = rpc.getblock(block_hash);
    vector<string> merkle_leaves;

    if (!block.isMember("tx")) {
      throw runtime_error("invalid txn");
    }
    for (auto itr : block["tx"]) {
      merkle_leaves.push_back(itr.asString());
    }

    auto tx_idx = distance(
            merkle_leaves.begin(),
            find(merkle_leaves.begin(), merkle_leaves.end(), txid));

    if (tx_idx >= merkle_leaves.size()) {
      throw runtime_error("invalid block");
    };

    cout << "Generating Merkle branch for " << txid << " (index=" << tx_idx << ") in block #" << block["height"] << endl;

    merkGenPathHEX(merkle_leaves, tx_idx);

    cout << "Merkle root of block #" << block["height"] << ": " << block["merkleroot"].asString() << endl;

  } catch (const bitcoinRPCException &e) {
    cerr << e.what() << endl;
    return -1;
  }
  return 0;
}

int test_feed_blocks() {
  return test_merkle_proof();

  bitcoinRPC rpc;

  int test_block_1[3]{10000, 10001, 10002};
  int test_block_2[4]{10003, 10004, 10005, 10007};

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
