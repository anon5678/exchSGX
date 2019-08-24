#include "bitcoind-merkleproof.h"
#include <string.h>

#include <algorithm>
#include <chrono>
#include <string>
#include <thread>
#include <vector>

#include <log4cxx/logger.h>
#include <log4cxx/propertyconfigurator.h>

#include "merkpath/merkpath.h"
#include "rpc/bitcoind-client.h"
#include "Enclave_u.h"
#include "config.h"

namespace exch
{
namespace bitcoin
{
log4cxx::LoggerPtr logger(
    log4cxx::Logger::getLogger("bitcoind-merkleproof.cpp"));
}
}  // namespace exch

using namespace std;
using exch::bitcoin::logger;

//#ifdef DEMO
extern Config conf;
//#endif

string getRawTransaction(const string &txid)
{
  Bitcoind rpc;
  return rpc.getrawtransaction(txid, false).asString();
}

bool getConfirmedHeader(
    const string &txid, const int NUM_CONFIRMATION, unsigned char *header)
{
  Bitcoind rpc;
  try {
    Json::Value txn = rpc.getrawtransaction(txid, true);

    if (!txn.isMember("blockhash")) {
      throw runtime_error("invalid txn");
    }

    string block_hash = txn["blockhash"].asString();
    Json::Value block = rpc.getblock(block_hash);
    if (block["confirmations"] > NUM_CONFIRMATION) {
      strcpy((char *)header, block_hash.c_str());
    } else {
      LOG4CXX_INFO(logger, "not enough confirmation yet");
      return false;
    }
  } catch (const BitcoindRPCException &e) {
    throw runtime_error(e.what());
  }
  return true;
}

TxInclusion isTxIncluded(const string &txid)
{
  Bitcoind rpc;
  int i = 0;
  LOG4CXX_INFO(logger, "testing if " << txid << " is confirmed");
  while (true) {
    try {
      Json::Value txn = rpc.getrawtransaction(txid, false);
      if (!txn.isNull()) return TxInclusion::Yes;
    } catch (const exception &e) {
      if (string(e.what()).find("No such mempool or blockchain transaction") !=
          string::npos) {
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

MerkleProof buildTxInclusionProof(const string &txid)
{
  Bitcoind rpc;

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

    LOG4CXX_INFO(
        logger,
        "generating a merkle proof for tx (index=" << tx_idx << ") in block #"
                                                   << block["height"]);
    LOG4CXX_INFO(logger, "block hash=" << block_hash);

    MerkleProof proof = loopMerkleProof(merkle_leaves, tx_idx);

    proof.set_block(block_hash);
    proof.set_tx_raw(tx_raw_hex);

    string calc_root = proof.verify();
    if (calc_root == block["merkleroot"].asString()) {
      LOG4CXX_INFO(
          logger, "succeed. merkle root in block header is: " << calc_root);
      return proof;
    } else {
      LOG4CXX_DEBUG(logger, calc_root << " " << block["merkleroot"].asString());
      throw runtime_error("failed to generate a valid proof. Try again later.");
    }
  } catch (const BitcoindRPCException &e) {
    throw runtime_error(e.what());
  }
}

int sendTxToBlockchain(int index, const char* tx_hex) {
    try {
    if (index == 1) {
#ifdef DEMO
        if (conf.getFailure() && conf.getIsFairnessLeader()) return 0;
#endif
        Bitcoind rpc;
        LOG4CXX_INFO(logger, "start sending tx to bitcoin");
        rpc.sendrawtransaction(string(tx_hex));
        LOG4CXX_INFO(logger, "tx sent to bitcoin");
#ifdef DEMO
        rpc.generatetoaddress(2, "muEPF2wfm1QdLy3LKocBQiW8g73WpzFq72"); //TODO: just for demo, note that the last generated block is not fed into blockfifo!!!
#endif
        LOG4CXX_INFO(logger, "tx mined in bitcoin");
    } else {
        Bitcoind rpc("localhost", 8335);
        LOG4CXX_INFO(logger, "start sending tx to litecoin");
        rpc.sendrawtransaction(string(tx_hex));
        LOG4CXX_INFO(logger, "tx sent to litecoin");
#ifdef DEMO
        rpc.generatetoaddress(2, "muEPF2wfm1QdLy3LKocBQiW8g73WpzFq72"); //TODO: just for demo, note that the last generated block is not fed into blockfifo!!!
        LOG4CXX_INFO(logger, "tx mined in litecoin");
#endif
    }
    } catch (const BitcoindRPCException &e) {
        throw runtime_error(e.what());
    }
    return 0;
}

