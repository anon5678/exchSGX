#include "merkpath/merkpath.h"
#include "Utils.h"
#include "rpc.h"

#include <algorithm>
#include <fstream>

#include <log4cxx/logger.h>
#include <log4cxx/propertyconfigurator.h>
log4cxx::LoggerPtr logger(log4cxx::Logger::getLogger("merkleproof"));

int main(int argc, const char *argv[]) {
  if (argc < 2) {
    cout << "Usage: " << argv[0] << " txid" << endl;
    exit(-1);
  }

  log4cxx::PropertyConfigurator::configure(LOGGING_CONF);

  bitcoinRPC rpc;

  string txid = string(argv[1]);

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
    for (auto& tx : block["tx"]) {
      merkle_leaves.push_back(tx.asString());
    }

    auto tx_idx = distance(
        merkle_leaves.begin(),
        find(merkle_leaves.begin(), merkle_leaves.end(), txid));

    if (tx_idx >= merkle_leaves.size()) {
      throw runtime_error("invalid block");
    };

    LOG4CXX_INFO(logger, "Generating proof for tx (index=" << tx_idx << ") in block #" << block["height"]);
    LOG4CXX_INFO(logger, "block hash=" << block_hash);

    MerkleProof proof = loopMerkleProof(merkle_leaves, tx_idx);

    proof.set_block(block_hash);
    proof.set_tx_raw(tx_raw_hex);
    string calc_root = proof.verify();

    if (calc_root == block["merkleroot"].asString()) {
      LOG4CXX_INFO(logger, "succeed. Merkle root is: " << calc_root);

      proof.dumpJSON(cout);
      cout << endl;

      string filename = txid.substr(0, 6) + ".merkle";
      ofstream out(filename);
      proof.dumpJSON(out);
      out.close();

      LOG4CXX_INFO(logger, "Proof is dumped to " << filename);
    }
    else {
      LOG4CXX_ERROR(logger, "failed to generate a valid proof. Try again later.");
      return -1;
    }
  } catch (const bitcoinRPCException &e) {
    LOG4CXX_ERROR(logger, e.what());
    return -1;
  }
  return 0;
}
