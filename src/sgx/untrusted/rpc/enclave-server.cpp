#include "enclave-server.h"

#include <assert.h>
#include <iostream>

#include <log4cxx/logger.h>
#include <log4cxx/propertyconfigurator.h>
#include <boost/asio/deadline_timer.hpp>
#include <boost/asio/io_service.hpp>
#include <boost/bind/bind.hpp>
#include <future>
#include <memory>

#include "../../common/merkle_data.h"
#include "../../common/utils.h"
#include "../Enclave_u.h"
#include "../bitcoind-merkleproof.h"
#include "../enclave-utils.h"
#include "../merkpath/merkpath.h"
#include "fairness-client.h"

namespace exch
{
namespace rpc
{
log4cxx::LoggerPtr logger(
    log4cxx::Logger::getLogger("rpc/enclave-server.cpp"));
}
}  // namespace exch

using exch::rpc::logger;

EnclaveRPC::EnclaveRPC(
    sgx_enclave_id_t eid, jsonrpc::AbstractServerConnector &conn)
    : exch::rpc::AbsServer(conn), eid(eid)
{
}

bool EnclaveRPC::appendBlock2FIFO(const std::string &block_header)
{
  throw runtime_error("should not call appendBlock2FIFO");
  /*
  int ret;
  sgx_status_t st = ecall_append_block_to_fifo(eid, &ret, block_header.c_str());
  if (st != SGX_SUCCESS || ret != 0) {
    LOG4CXX_INFO(logger, "cannot append");
    return false;
  }
  return true;
  */
}

namespace exch
{
namespace bitcoin
{
namespace deposit
{
namespace JSON
{
constexpr auto TX_HASH = "tx";
constexpr auto TX_RAW = "tx_raw";
constexpr auto BLOCK_HASH = "block";
constexpr auto DIVREC = "dirvec";
constexpr auto BRANCH = "branch";
constexpr auto RECV_ADDR = "deposit_recv_addr";
constexpr auto REFUND_ADDR = "deposit_refund_addr";
constexpr auto DEPOSIT_TIMEOUT = "deposit_timeout";
}  // namespace JSON
}  // namespace deposit
}  // namespace bitcoin
}  // namespace exch

using namespace exch::bitcoin;

#include <boost/asio/io_service.hpp>

extern shared_ptr<boost::asio::io_service> io_service;
extern sgx_enclave_id_t eid;

const int TIMEOUT_T1_SECOND = 2;
const int TIMEOUT_T2_SECOND = 10;
const int TRY_SECOND = 2;
const int INTER_PERIOD_MILLISECOND = 1000;
const int NUM_COMFIRMATION = 0; //TODO: modify confirmation number

/// Deposit money to public_key by providing a merkle_proof
bool EnclaveRPC::deposit(
    const Json::Value &merkle_proof, const string &public_key)
{
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

    for (Json::Value::const_iterator it = _merkle_branch_JSON.begin();
         it != _merkle_branch_JSON.end();
         it++) {
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

    bitcoin_deposit_t deposit{
        p,
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
  } catch (const std::exception &e) {
    LOG4CXX_ERROR(logger, "exception: " << e.what());
    return false;
  }
}

void checkConfirmation(unsigned char *tx1_id, unsigned char *tx1_cancel_id)
{
  int ret;
  int attempts = 0;
  bool find = false;

  while (attempts++ < TIMEOUT_T1_SECOND * 1000 / INTER_PERIOD_MILLISECOND) {
    if (!find) {
      TxInclusion tx_one_confirmed =
          isTxIncluded(reinterpret_cast<char *>(tx1_id));
      if (tx_one_confirmed == TxInclusion::Yes) {
        find = true;
        string rawtx = getRawTransaction(reinterpret_cast<char *>(tx1_id));
        // LOG4CXX_DEBUG(logger, rawtx);
        unsigned char *tx1 = reinterpret_cast<unsigned char *>(
            const_cast<char *>(rawtx.c_str()));
        onTxOneInMempool(eid, &ret, tx1, rawtx.size());
      }
    }
    this_thread::sleep_for(chrono::milliseconds(INTER_PERIOD_MILLISECOND));
  }

  if (!find) {
    afterTimeout(eid, &ret);
    this_thread::sleep_for(chrono::seconds(TIMEOUT_T2_SECOND));
  } else {
    this_thread::sleep_for(
        chrono::seconds(TIMEOUT_T2_SECOND - TIMEOUT_T1_SECOND));
    TxInclusion tx_one_confirmed =
        isTxIncluded(reinterpret_cast<char *>(tx1_id));
    unsigned char header[64];
    bool confirmed = getConfirmedHeader(
        reinterpret_cast<char *>(tx1_id), NUM_COMFIRMATION, header);
    if (tx_one_confirmed != TxInclusion::Yes || !confirmed) {
      afterTimeout(eid, &ret);
      this_thread::sleep_for(chrono::seconds(TIMEOUT_T2_SECOND));
    }
  }

  attempts = 0;
  while (attempts++ <= TRY_SECOND * 1000 / INTER_PERIOD_MILLISECOND) {
    try {
      TxInclusion tx_one_confirmed =
          isTxIncluded(reinterpret_cast<char *>(tx1_id));
      unsigned char header[64];
      bool confirmed = getConfirmedHeader(
          reinterpret_cast<char *>(tx1_id), NUM_COMFIRMATION, header);
      if (tx_one_confirmed == TxInclusion::Yes && confirmed) {
        MerkleProof proof =
            buildTxInclusionProof(reinterpret_cast<char *>(tx1_id));
        LOG4CXX_INFO(logger, "tx1 confirmed on Bitcoin");
        const auto *serialized = proof.serialize();
        int ret;
        auto st = onTxOneConfirmation(eid, &ret, header, 64, serialized);
        if (st != SGX_SUCCESS || ret != 0) {
          LOG4CXX_WARN(
              logger, "failed to call enclave. " << get_sgx_error_msg(st));
        }
        return;
      }
    } catch (const std::exception &e) {
      LOG4CXX_ERROR(logger, e.what());
    }

    try {
      TxInclusion tx_one_cancelled =
          isTxIncluded(reinterpret_cast<char *>(tx1_cancel_id));
      unsigned char header[64];
      bool confirmed = getConfirmedHeader(
          reinterpret_cast<char *>(tx1_cancel_id), NUM_COMFIRMATION, header);
      if (tx_one_cancelled == TxInclusion::Yes && confirmed) {
        MerkleProof proof =
            buildTxInclusionProof(reinterpret_cast<char *>(tx1_cancel_id));
        LOG4CXX_INFO(logger, "tx1_cancel confirmed on Bitcoin");
        const auto *serialized = proof.serialize();
        int ret;
        auto st = onTxOneConfirmation(eid, &ret, header, 64, serialized);
        if (st != SGX_SUCCESS || ret != 0) {
          LOG4CXX_WARN(
              logger, "failed to call enclave. " << get_sgx_error_msg(st));
          get_sgx_error_msg(st);
        }
        return;
      }
    } catch (const std::exception &e) {
      LOG4CXX_ERROR(logger, e.what());
    }
    this_thread::sleep_for(chrono::milliseconds(INTER_PERIOD_MILLISECOND));
  }
  LOG4CXX_DEBUG(logger, "Fairness protocol fails. Don't know what to do...");
}

/*
 * Fairness protocol (follower part)
 */
// This function is called a follower when receiving the initial messages from
// the leader
void _onMessageFromFairnessLeader(string settlementPkg)
{
  int ret;
  unsigned char *tx1_id = (unsigned char *)malloc(65);
  tx1_id[64] = 0;
  unsigned char *tx1_cancel_id = (unsigned char *)malloc(65);
  tx1_cancel_id[64] = 0;
  onMessageFromFairnessLeader(
      eid,
      &ret,
      reinterpret_cast<const unsigned char *>(settlementPkg.data()),
      settlementPkg.size(),
      tx1_id,
      tx1_cancel_id);
  checkConfirmation(tx1_id, tx1_cancel_id);
}

bool EnclaveRPC::distributeSettlementPkg(const std::string &settlementPkg)
{
  LOG4CXX_INFO(
      logger, "get " << settlementPkg.size() << "bytes from the leader");
  io_service->post(boost::bind(&_onMessageFromFairnessLeader, settlementPkg));

  return true;
}

/*
 * Fairness protocol (leader part)
 */
// This function is called on a leader when receiving message from the followers
void _ackSettlementPkg(string ack)
{
  int ret;
  unsigned char *tx1_id = (unsigned char *)malloc(65);
  tx1_id[64] = 0;
  unsigned char *tx1_cancel_id = (unsigned char *)malloc(65);
  tx1_cancel_id[64] = 0;
  onAckFromFairnessFollower(
      eid,
      &ret,
      reinterpret_cast<const unsigned char *>(ack.data()),
      ack.size(),
      tx1_id,
      tx1_cancel_id);
  if (strlen(reinterpret_cast<char *>(tx1_id)) != 0)
    checkConfirmation(tx1_id, tx1_cancel_id);
}

bool EnclaveRPC::ackSettlementPkg(const std::string &ack)
{
  LOG4CXX_DEBUG(logger, "receiving ack from a backup");
  io_service->post(boost::bind(&_ackSettlementPkg, ack));

  return true;
}
