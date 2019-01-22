#include "enclave-rpc-server-impl.h"

#include <iostream>
#include <assert.h>

#include <boost/bind/bind.hpp>
#include <log4cxx/logger.h>
#include <log4cxx/propertyconfigurator.h>

#include "merkpath/merkpath.h"
#include "Enclave_u.h"

namespace exch {
namespace rpc {
log4cxx::LoggerPtr logger(log4cxx::Logger::getLogger("enclave-rpc-server-impl.cpp"));
}
}

using exch::rpc::logger;

EnclaveRPC::EnclaveRPC(sgx_enclave_id_t eid, jsonrpc::AbstractServerConnector &conn)
    : exch::rpc::AbsServer(conn), eid(eid) {}

bool EnclaveRPC::appendBlock2FIFO(const std::string &block_header) {
  int ret;
  sgx_status_t st = ecall_append_block_to_fifo(eid, &ret, block_header.c_str());
  if (st != SGX_SUCCESS || ret != 0) {
    LOG4CXX_INFO(logger, "cannot append");
    return false;
  }
  return true;
}

namespace exch {
namespace bitcoin {
namespace deposit {
namespace JSON {
constexpr auto TX_HASH = "tx";
constexpr auto TX_RAW = "tx_raw";
constexpr auto BLOCK_HASH = "block";
constexpr auto DIVREC = "dirvec";
constexpr auto BRANCH = "branch";
constexpr auto RECV_ADDR = "deposit_recv_addr";
constexpr auto REFUND_ADDR = "deposit_refund_addr";
constexpr auto DEPOSIT_TIMEOUT = "deposit_timeout";
}
}
}
}

using namespace exch::bitcoin;

#include <boost/asio/io_service.hpp>

extern shared_ptr<boost::asio::io_service> io_service;
extern sgx_enclave_id_t eid;

/// Deposit money to public_key by providing a merkle_proof
bool EnclaveRPC::deposit(const Json::Value &merkle_proof, const string &public_key) {
  int ret;
  sgx_status_t st;

  LOG4CXX_INFO(logger, "depositing");
  LOG4CXX_DEBUG(logger, merkle_proof.toStyledString());

  try {
    if (!merkle_proof.isMember(deposit::JSON::TX_HASH) ||
        !merkle_proof.isMember(deposit::JSON::TX_RAW) ||
        !merkle_proof.isMember(deposit::JSON::BLOCK_HASH) ||
        !merkle_proof.isMember(deposit::JSON::DIVREC) ||
        !merkle_proof.isMember(deposit::JSON::BRANCH) ||
        !merkle_proof.isMember(deposit::JSON::RECV_ADDR) ||
        !merkle_proof.isMember(deposit::JSON::REFUND_ADDR) ||
        !merkle_proof.isMember(deposit::JSON::DEPOSIT_TIMEOUT) ||
        !merkle_proof[deposit::JSON::DIVREC].isInt() ||
        !merkle_proof[deposit::JSON::BRANCH].isArray() ||
        !merkle_proof[deposit::JSON::DEPOSIT_TIMEOUT].isUInt64()) {
      LOG4CXX_ERROR(logger, "invalid proof");
      return false;
    }

    Json::Value _merkle_branch_JSON = merkle_proof[deposit::JSON::BRANCH];
    vector<string> _merkle_branch;

    for (Json::Value::const_iterator it = _merkle_branch_JSON.begin(); it != _merkle_branch_JSON.end(); it++) {
      _merkle_branch.push_back(it->asString());
    }

    MerkleProof proof(
        merkle_proof[deposit::JSON::TX_HASH].asString(),
        _merkle_branch,
        merkle_proof[deposit::JSON::DIVREC].asInt());

    proof.set_block(merkle_proof[deposit::JSON::BLOCK_HASH].asString());
    proof.set_tx_raw(merkle_proof[deposit::JSON::TX_RAW].asString());

    merkle_proof_t *p = merkle_proof_init(proof.proof_size());
    proof.serialize(p);

    bitcoin_deposit_t deposit{p,
                              merkle_proof[deposit::JSON::TX_RAW].asCString(),
                              merkle_proof[deposit::JSON::BLOCK_HASH].asCString(),
                              merkle_proof[deposit::JSON::RECV_ADDR].asCString(),
                              merkle_proof[deposit::JSON::REFUND_ADDR].asCString(),
                              merkle_proof[deposit::JSON::DEPOSIT_TIMEOUT].asUInt64(),
                              public_key.c_str()};

    st = ecall_bitcoin_deposit(eid, &ret, &deposit);
    if (st != SGX_SUCCESS || ret != 0) {
      LOG4CXX_ERROR(logger, "failed to make ecall st=" << hex << st);
      return false;
    }

    return true;
  }
  catch (const std::exception &e) {
    LOG4CXX_ERROR(logger, "exception: " << e.what());
    return false;
  }
}

/*
 * Fairness protocol (follower part)
 */
// This function is called a follower when receiving the initial messages from the leader
void _onMessageFromFairnessLeader(string settlementPkg) {
  int ret;
  unsigned char *tx1_id = (unsigned char*)malloc(65);
  onMessageFromFairnessLeader(eid,
                              &ret,
                              reinterpret_cast<const unsigned char *>(settlementPkg.data()),
                              settlementPkg.size(),
                              tx1_id);
  LOG4CXX_INFO(logger, "look up tx1_id: " << tx1_id << " in mempool");
  //TODO: look up tx1_id in mempool and call onTxOneInMempool once found
}

bool EnclaveRPC::distributeSettlementPkg(const std::string &settlementPkg) {
  LOG4CXX_INFO(logger, "get " << settlementPkg.size() << "bytes from the leader");
  io_service->post(boost::bind(&_onMessageFromFairnessLeader, settlementPkg));

  return true;
}

/*
 * Fairness protocol (leader part)
 */
// This function is called on a leader when receiving message from the followers
void _ackSettlementPkg(string ack) {
  int ret;
  onAckFromFairnessFollower(eid,
                            &ret,
                            reinterpret_cast<const unsigned char *>(ack.data()),
                            ack.size());

}

bool EnclaveRPC::ackSettlementPkg(const std::string &ack) {
  LOG4CXX_DEBUG(logger, "receiving ack from a backup");
  io_service->post(boost::bind(&_ackSettlementPkg, ack));

  return true;
}
