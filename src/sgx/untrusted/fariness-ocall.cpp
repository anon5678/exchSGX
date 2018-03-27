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

#include "bitcoind-merkleproof.h"
#include "../common/merkle_data.h"

void expectTxOnBitcoin(const string& txid) {
  LOG4CXX_INFO(logger, "waiting for " << txid);

  MerkleProof proof = buildTxInclusionProof(txid);

  const auto* serialized = proof.serialize();

  LOG4CXX_INFO(logger, "tx confirmed on Bitcoin");

  int ret;
  auto st = onTxOneCommitted(eid, &ret, serialized);
  if (st != SGX_SUCCESS || ret != 0) {
    LOG4CXX_WARN(logger, "failed to call enclave");
  }
}

int commitTxOne(const unsigned char* tx, size_t size) {
  LOG4CXX_INFO(logger, "sending tx to Bitcoin");

  // currently `tx` is a string for txid
  string txid((char*) tx, size);

  // wait for a confirmation
  async(expectTxOnBitcoin, txid );

  return 0;
}
