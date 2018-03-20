#include "enclave-rpc-client-impl.h"
#include "Enclave_u.h"
#include "../common/utils.h"

#include <log4cxx/logger.h>
#include <thread>
#include <chrono>
#include <random>

using exch::rpc::Client;
using namespace std;

namespace exch {
namespace rpc {
namespace client {

log4cxx::LoggerPtr logger(log4cxx::Logger::getLogger("enclave-rpc-client-imp.cpp"));

}
}
};

using exch::rpc::client::logger;

// ocall
int sendMessagesToFairnessFollower(const char* host, int port, const unsigned char* msg, size_t size) {
  try {
    Client c(host, port);
    LOG4CXX_DEBUG(logger, "get message from the enclave; to be sent to followers");
    c.distributeSettlementPkg(string((char*) msg, size));

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

// ocall
int sendAckToFairnessLeader(const char* host, int port, const unsigned char* msg, size_t size) {
  try {
    LOG4CXX_INFO(logger, "get ack from the enclave; to be sent to the leader");

    // insert a random network latency for up to 3000 ms
    // TODO: remove this when deployed in real network
    this_thread::sleep_for(chrono::milliseconds(std::rand() % 3000));


    Client c(host, port);
    c.ackSettlementPkg(string((const char*) msg, size));
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
