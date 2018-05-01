#include "fairness-ocall.h"

#include "Enclave_u.h"
#include "bitcoind-merkleproof.h"
#include "../common/merkle_data.h"
#include "Utils.h"

#include <log4cxx/logger.h>
#include <future>

#include <boost/asio/io_service.hpp>
#include <boost/bind/bind.hpp>

namespace exch {

namespace fairness {
namespace ocalls {
log4cxx::LoggerPtr logger(log4cxx::Logger::getLogger("fairness-ocall.cpp"));
}
}
};

#include <memory>
#include <boost/asio/io_service.hpp>
#include <boost/asio/deadline_timer.hpp>
#include "../common/utils.h"

using namespace std;
using exch::fairness::ocalls::logger;
using exch::rpc::Client;

extern shared_ptr<boost::asio::io_service> io_service;
extern unique_ptr<boost::asio::deadline_timer> fairnessTimer;
extern sgx_enclave_id_t eid;

// ocall
int fairnessProtocolForLeader(
    const char *tx_one_id,
    const char *tx_one_cancel_id,
    const unsigned char *tx,
    size_t size) {

  // wait for a confirmation
  // TODO: add actual code to send tx
  LOG4CXX_INFO(logger, "sending " << size << " bytes to bitcoin");

  // set a small timeout so that the leader can optimistically proceed
  return fairnessProtocolForFollower(tx_one_id, tx_one_cancel_id, 0);
}

// ocall
void fairnessTimerHandler(
    const boost::system::error_code &error,
    string tx_one_id,
    string tx_one_cancel_id) {
  if (error) {
    LOG4CXX_INFO(logger, "fairness timer: " << error);
    return;
  }
  uint8_t tx_buffer[1024];
  try {
    TxInclusion tx_one_confirmed = isTxIncluded(tx_one_id);
    TxInclusion tx_one_cancelled = isTxIncluded(tx_one_cancel_id);

    if (tx_one_confirmed == TxInclusion::Yes) {
      MerkleProof proof = buildTxInclusionProof(tx_one_id);
      LOG4CXX_INFO(logger, "tx confirmed on Bitcoin");
      const auto *serialized = proof.serialize();

      int ret;
      auto st = onTxOneCommitted(eid, &ret, serialized, tx_buffer, sizeof tx_buffer);
      if (st != SGX_SUCCESS || ret != 0) {
        LOG4CXX_WARN(logger, "failed to call enclave");
        print_error_message(st);
      }

      // TODO: add actual code
      LOG4CXX_INFO(logger, "now sending tx2");
      return;
    }

    if (tx_one_cancelled == TxInclusion::Yes) {
      int ret;
      auto st = onTxOneNotCommitted(eid, &ret, tx_buffer, sizeof tx_buffer);
      if (st != SGX_SUCCESS || ret != 0) {
        LOG4CXX_WARN(logger, "failed to call enclave");
        print_error_message(st);
      }

      // TODO: add actual code
      LOG4CXX_INFO(logger, "now send cancellation")
      return;
    }

    LOG4CXX_ERROR(logger, "don't know what to do");

    return;
  }
  catch (const exception &e) {
    LOG4CXX_ERROR(logger, e.what());
    return;
  }
}

int fairnessProtocolForFollower(
    const char *tx_one_id,
    const char *tx_one_cancel_id,
    unsigned int sec) {

  if (!fairnessTimer) {
    fairnessTimer = unique_ptr<boost::asio::deadline_timer>(new boost::asio::deadline_timer(*io_service));
  }

  fairnessTimer->expires_from_now(boost::posix_time::seconds(sec));
  fairnessTimer->async_wait(boost::bind(fairnessTimerHandler, _1, string(tx_one_id), string(tx_one_cancel_id)));

  LOG4CXX_DEBUG(logger, "fairnessTimerHandler will be called after " << sec << " seconds.") ;

  return 0;
}

static void _sendMessageToFairnessFollower(string host, int port, const string &msg) {
  Client c(host, port);
  c.distributeSettlementPkg(msg);
}

// ocall
int sendMessagesToFairnessFollower(const char *host, int port, const unsigned char *msg, size_t size) {
  try {
    LOG4CXX_DEBUG(logger, "sending msg to " << host << ":" << port);
    io_service->post(boost::bind(&_sendMessageToFairnessFollower, string(host), port, string((char *) msg, size)));

    return 0;
  }
  catch (const exception &e) {
    LOG4CXX_WARN(logger, "cannot send message to follower: " << e.what());
    return -1;
  }
  catch (...) {
    LOG4CXX_WARN(logger, "error happened");
    cerr << "Error happened" << endl;
    return -1;
  }
}

void _sendAckToFairnessLeader(string host, int port, const string &msg) {
  Client c(host, port);
  c.ackSettlementPkg(msg);
}

// ocall
int sendAckToFairnessLeader(const char *host, int port, const unsigned char *msg, size_t size) {
  try {
    LOG4CXX_INFO(logger, "sending ack to " << host << ":" << port);

    // insert a random network latency for up to 3000 ms
    // TODO: remove this when deployed in real network
    this_thread::sleep_for(chrono::milliseconds(std::rand() % 3000));

    io_service->post(boost::bind(&_sendAckToFairnessLeader, string(host), port, string((char *) msg, size)));
    return 0;
  }
  catch (const exception &e) {
    LOG4CXX_WARN(logger, "cannot send ack to leader: " << e.what());
    return -1;
  }
  catch (...) {
    LOG4CXX_WARN(logger, "error happened");
    return -1;
  }
}
