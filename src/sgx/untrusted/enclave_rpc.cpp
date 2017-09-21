#include "enclave_rpc.h"
#include "Enclave_u.h"

#include "sgx_error.h"
#include "merkpath/merkpath.h"

#include <iostream>
#include <utility>

#include <log4cxx/logger.h>
#include <log4cxx/propertyconfigurator.h>

namespace exch {
namespace RPC {
log4cxx::LoggerPtr logger(log4cxx::Logger::getLogger("exch.RPC"));
}
}

using exch::RPC::logger;

EnclaveRPC::EnclaveRPC(sgx_enclave_id_t eid,
                       jsonrpc::AbstractServerConnector &conn)
    : AbstractEnclaveRPC(conn), eid(eid) {}

bool EnclaveRPC::appendBlock2FIFO(const std::string &block_header) {
  int ret;
  sgx_status_t st = ecall_append_block_to_fifo(eid, &ret, block_header.c_str());
  if (st != SGX_SUCCESS || ret != 0) {
    std::cerr << "cannot append block" << std::endl;
    return false;
  }
  return true;
}

bool EnclaveRPC::deposit(const Json::Value &merkle_proof, const string &public_key) {
  int ret;
  sgx_status_t st;

  cout << "depositing" << endl;
  cout << "proof: " << merkle_proof << endl;
  cout << "public key: " << public_key << endl;

  try {
    if (!merkle_proof.isMember("tx") ||
        !merkle_proof.isMember("block") ||
        !merkle_proof.isMember("dirvec") ||
        !merkle_proof["dirvec"].isInt() ||
        !merkle_proof.isMember("branch") ||
        !merkle_proof["branch"].isArray()) {
      LOG4CXX_ERROR(logger, "invalid proof");
      return false;
    }

    Json::Value _merkle_branch_JSON = merkle_proof["branch"];
    vector<string> _merkle_branch;

    for (Json::Value::const_iterator it = _merkle_branch_JSON.begin(); it != _merkle_branch_JSON.end(); it++) {
      _merkle_branch.push_back(it->asString());
    }

    MerkleProof proof(merkle_proof["tx"].asString(), _merkle_branch, merkle_proof["dirvec"].asInt());
    proof.set_block(merkle_proof["block"].asString());

    merkle_proof_t *p = merkle_proof_init(proof.proof_size());
    proof.serialize(p);

    st = merkle_proof_verify(eid, &ret, p);
    if (st != SGX_SUCCESS || ret != 0) {
      LOG4CXX_ERROR(logger, "failed to make ecall");
      return false;
    }
  }

  catch (const std::exception &e) {
    LOG4CXX_ERROR(logger, "exception: " << e.what());
    return false;
  }
  return true;
}
