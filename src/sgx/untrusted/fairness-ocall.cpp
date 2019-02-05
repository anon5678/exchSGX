#include "fairness-ocall.h"

#include "Enclave_u.h"
#include "bitcoind-merkleproof.h"
#include "../common/merkle_data.h"
#include "../common/utils.h"
#include "Utils.h"

#include <future>
#include <memory>
#include <boost/asio/io_service.hpp>
#include <boost/asio/deadline_timer.hpp>
#include <boost/bind/bind.hpp>
#include <log4cxx/logger.h>

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

//using boost::placeholders::_1;

namespace aio = boost::asio;

shared_ptr<aio::io_service> io_service;
unique_ptr<boost::asio::deadline_timer> fairnessTimer;

extern sgx_enclave_id_t eid;

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

//TODO: send real tx to bitcoin
int sendTxToBlockchain() {
    return 0;
}

