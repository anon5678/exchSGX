#include "Enclave_u.h"

#include <log4cxx/logger.h>

#include <future>

namespace exch {
namespace fairness {
namespace ocalls {

log4cxx::LoggerPtr logger(log4cxx::Logger::getLogger("fairness_call.cpp"));

}
}
};

using exch::fairness::ocalls::logger;
using namespace std;

extern sgx_enclave_id_t eid;

void expectTxOnBitcoin(string txid) {
  this_thread::sleep_for(chrono::seconds(3));

  LOG4CXX_INFO(logger, "tx confirmed on Bitcoin");

  int ret;
  auto st = onTxOneCommitted(eid, &ret);
  if (st != SGX_SUCCESS || ret != 0) {
    LOG4CXX_WARN(logger, "failed to call enclave");
  }
}

int commitTxOne() {
  LOG4CXX_INFO(logger, "sending tx to Bitcoin");

  // wait for a confirmation

  async(expectTxOnBitcoin, "transaction id goes here");

  return 0;
}
