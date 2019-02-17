#include "bitcoind-merkleproof.h"

#include <string>
#include <vector>
#include <algorithm>
#include <thread>
#include <chrono>

#include <log4cxx/logger.h>
#include <log4cxx/propertyconfigurator.h>

#include "rpc/bitcoind-client.h"
#include "merkpath/merkpath.h"

namespace exch {
namespace bitcoin {
log4cxx::LoggerPtr logger(log4cxx::Logger::getLogger("bitcoind-merkleproof.cpp"));
}
}

using namespace std;
using exch::bitcoin::logger;

string getRawTransaction(const string &txid) {
    bitcoinRPC rpc;
    return rpc.getrawtransaction(txid, false).asString();
} 

TxInclusion isTxIncluded(const string &txid) {
  bitcoinRPC rpc;
  int i = 0;
  LOG4CXX_INFO(logger, "testing if " << txid << " is confirmed");
  while (true) {
    try {
      Json::Value txn = rpc.getrawtransaction(txid, false);
      if (!txn.isNull())
        return TxInclusion::Yes;
    }
    catch (const exception &e) {
      if (string(e.what()).find("No such mempool or blockchain transaction") != string::npos) {
        LOG4CXX_INFO(logger, "tx " << txid << " is not confirmed");
        return TxInclusion::No;
      }
      LOG4CXX_DEBUG(logger, "bitcoinRPCException: " << e.what());
      // TODO: handle the error and retry
      if (i++ > 10) {
        return TxInclusion::NotSure;
      }
      /// Sleep for one second then retry
      this_thread::sleep_for(chrono::seconds(1));
    }
    break;
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
      LOG4CXX_DEBUG(logger, calc_root << " "<< block["merkleroot"].asString());
      throw runtime_error("failed to generate a valid proof. Try again later.");
    }
  } catch (const bitcoinRPCException &e) {
    throw runtime_error(e.what());
  }
}
