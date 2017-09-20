#include "blockfeeding.h"
#include "Enclave_u.h"
#include "rpc.h"

#include <algorithm>
#include <iostream>
#include <string>
#include <vector>
#include "merkpath/merkpath.h"

using namespace std;

#if false
int test_merkle_proof() {
  // testMerk(); //return 0;
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

#endif
