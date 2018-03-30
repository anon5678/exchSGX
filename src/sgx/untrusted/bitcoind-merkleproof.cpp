#include "bitcoind-merkleproof.h"

#include <string>
#include <vector>
#include <algorithm>

#include <log4cxx/logger.h>
#include <log4cxx/propertyconfigurator.h>

#include "bitcoind-rpc.h"
#include "merkpath/merkpath.h"

namespace exch {
namespace bitcoin {
log4cxx::LoggerPtr logger(log4cxx::Logger::getLogger("bitcoind-merkleproof.cpp"));
}
}

using namespace std;
using exch::bitcoin::logger;

bool isTxIncluded(const string &txid) {
  bitcoinRPC rpc;
  int i = 0;
  while (true) {
    try {
      Json::Value txn = rpc.getrawtransaction(txid, false);
      return txn.isNull();
    }
    catch (const exception &e) {
      LOG4CXX_ERROR(logger, "cannot call isTxIncluded: " << e.what());
      // TODO: handle the error and retry
      if (i++ > 10) {
        return false;
      }
    }
  }
}

MerkleProof buildTxInclusionProof(const string &txid) {
  bitcoinRPC rpc;

  try {
    Json::Value txn = rpc.getrawtransaction(txid, true);
    string tx_raw_hex = rpc.getrawtransaction(txid, false).asString();

    if (!txn.isMember("blockhash")) {
      throw runtime_error("invalid txn");
    }

    string block_hash = txn["blockhash"].asString();
    Json::Value block = rpc.getblock(block_hash);
    vector<string> merkle_leaves;

    if (!block.isMember("tx")) {
      throw runtime_error("invalid txn");
    }
    for (auto &tx : block["tx"]) {
      merkle_leaves.push_back(tx.asString());
    }

    auto tx_idx = distance(
        merkle_leaves.begin(),
        find(merkle_leaves.begin(), merkle_leaves.end(), txid));

    if (tx_idx >= merkle_leaves.size()) {
      throw runtime_error("invalid block");
    };

    LOG4CXX_INFO(logger, "generating a merkle proof for tx (index=" << tx_idx << ") in block #" << block["height"]);
    LOG4CXX_INFO(logger, "block hash=" << block_hash);

    MerkleProof proof = loopMerkleProof(merkle_leaves, tx_idx);

    proof.set_block(block_hash);
    proof.set_tx_raw(tx_raw_hex);

    string calc_root = proof.verify();
    if (calc_root == block["merkleroot"].asString()) {
      LOG4CXX_INFO(logger, "succeed. merkle root in block header is: " << calc_root);
      return proof;
    } else {
      throw runtime_error("failed to generate a valid proof. Try again later.");
    }
  } catch (const bitcoinRPCException &e) {
    throw runtime_error(e.what());
  }

}
