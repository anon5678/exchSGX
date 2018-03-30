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

using namespace std;
using exch::fairness::ocalls::logger;
using exch::rpc::Client;

#include <boost/asio/io_service.hpp>

extern shared_ptr<boost::asio::io_service> io_service;
extern sgx_enclave_id_t eid;

// ocall
int commitTxOne(
    const char* tx_one_id,
    const char* tx_one_cancel_id,
    const unsigned char* tx, size_t size) {
  LOG4CXX_INFO(logger, "sending tx to Bitcoin");

  // wait for a confirmation
  LOG4CXX_INFO(logger, "sending tx1 to blockchain")

  // set a small timeout so that the leader can optimistically proceed
  fairnessProtocolForFollower(tx_one_id, tx_one_cancel_id, 0);

  return 0;
}

// ocall
void fairnessProtocolForFollower (
    const char* tx_one_id,
    const char* tx_one_cancel_id,
    unsigned int minutes) {
  uint8_t tx_buffer[1024];

  try {
    // sleep for timeout
    this_thread::sleep_for(chrono::minutes(minutes));

    bool tx_one_confirmed = isTxIncluded(tx_one_id);
    bool tx_one_cancelled = isTxIncluded(tx_one_cancel_id);

    // if none of the above boolean is true, we are undecided
    if (!(tx_one_confirmed || tx_one_cancelled)) {
      LOG4CXX_ERROR(logger, "don't know what to do");
      return;
    }

    if (tx_one_confirmed && tx_one_cancelled) {
      LOG4CXX_ERROR(logger, "we're in serious trouble");
      return;
    }

    if (tx_one_confirmed) {
      MerkleProof proof = buildTxInclusionProof(tx_one_id);
      LOG4CXX_INFO(logger, "tx confirmed on Bitcoin");
      const auto *serialized = proof.serialize();

      int ret;
      auto st = onTxOneCommitted(eid, &ret, serialized, tx_buffer, sizeof tx_buffer);
      if (st != SGX_SUCCESS || ret != 0) {
        LOG4CXX_WARN(logger, "failed to call enclave");
        print_error_message(st);
      }

      LOG4CXX_INFO(logger, "now sending tx2");

      return;
    }

    if (tx_one_cancelled) {
      int ret;
      auto st = onTxOneNotCommitted(eid, &ret, tx_buffer, sizeof tx_buffer);
      if (st != SGX_SUCCESS || ret != 0) {
        LOG4CXX_WARN(logger, "failed to call enclave");
        print_error_message(st);
      }

      LOG4CXX_INFO(logger, "now send cancellation")
    }

  }
  catch (const exception &e) {
    // TODO: retry if there is network problem and only call
    // the following ecall if the tx does not exist
    LOG4CXX_ERROR(logger, e.what());
  }
}

static void _sendMessageToFairnessFollower(string host, int port, const string& msg) {
  Client c(host, port);
  c.distributeSettlementPkg(msg);
  LOG4CXX_INFO(logger, "exiting _sendMessageToFairnessFollower");
}

// ocall
int sendMessagesToFairnessFollower(const char* host, int port, const unsigned char* msg, size_t size) {
  try {
    LOG4CXX_DEBUG(logger, "sending msg to " << host << ":" << port);
    io_service->post(boost::bind(&_sendMessageToFairnessFollower, string(host), port, string((char*)msg, size)));

    return 0;
  }
  catch (const exception& e) {
    LOG4CXX_WARN(logger, "cannot send message to follower: " << e.what());
    return -1;
  }
  catch (...) {
    LOG4CXX_WARN(logger, "error happened");
    cerr << "Error happened" << endl;
    return -1;
  }
}

void _sendAckToFairnessLeader(string host, int port, const string& msg) {
  Client c(host, port);
  c.ackSettlementPkg(msg);
  LOG4CXX_INFO(logger, "exiting _sendAckToFairnessLeader");
}

// ocall
int sendAckToFairnessLeader(const char* host, int port, const unsigned char* msg, size_t size) {
  try {
    LOG4CXX_INFO(logger, "sending ack to " << host << ":" << port);

    // insert a random network latency for up to 3000 ms
    // TODO: remove this when deployed in real network
    this_thread::sleep_for(chrono::milliseconds(std::rand() % 3000));

    io_service->post(boost::bind(&_sendAckToFairnessLeader, string(host), port, string((char*) msg, size)));
    return 0;
  }
  catch (const exception& e) {
    LOG4CXX_WARN(logger, "cannot send ack to leader: " << e.what());
    return -1;
  }
  catch (...) {
    LOG4CXX_WARN(logger, "error happened");
    return -1;
  }
}
