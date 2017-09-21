//
// Created by fanz on 9/20/17.
//
#include "merkpath/merkpath.h"
#include <log4cxx/logger.h>
#include <log4cxx/propertyconfigurator.h>
#include "Utils.h"
#include "rpc.h"
#include "Enclave_u.h"

#include <algorithm>

log4cxx::LoggerPtr logger(log4cxx::Logger::getLogger("merkleproof"));

int main(int argc, const char *argv[]) {
  if (argc < 2) {
    cout << "Usage: " << argv[0] << " txid" << endl;
    exit(-1);
  }

  log4cxx::PropertyConfigurator::configure(LOGGING_CONF);
  LOG4CXX_INFO(logger, "starting merkle proof");

  bitcoinRPC rpc;

  string txid = string(argv[1]);

  try {
    Json::Value txn = rpc.getrawtransaction(txid, true);

    if (!txn.isMember("blockhash")) {
      throw runtime_error("invalid txn");
    }

    string block_hash = txn["blockhash"].asString();
    Json::Value block = rpc.getblock(block_hash);
    vector<string> merkle_leaves;

    if (!block.isMember("tx")) {
      throw runtime_error("invalid txn");
    }
    for (auto tx : block["tx"]) {
      merkle_leaves.push_back(tx.asString());
    }

    auto tx_idx = distance(
        merkle_leaves.begin(),
        find(merkle_leaves.begin(), merkle_leaves.end(), txid));

    if (tx_idx >= merkle_leaves.size()) {
      throw runtime_error("invalid block");
    };

    LOG4CXX_INFO(logger, "Generating proof for tx (index="
        << tx_idx
        << ") in block #"
        << block["height"]);

    MerkleProof proof = loopMerkleProof(merkle_leaves, tx_idx);

    proof.output(cout);
    proof.verify();
    proof.serialize(nullptr);

    LOG4CXX_INFO(logger, "Merkle root of block #" << block["height"] << ": " << block["merkleroot"].asString());
  } catch (const bitcoinRPCException &e) {
    LOG4CXX_ERROR(logger, e.what());
    return -1;
  }
  return 0;
}
