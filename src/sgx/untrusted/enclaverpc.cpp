#include "enclaverpc.h"
#include "Enclave_u.h"

#include "sgx_error.h"

#include <iostream>
#include <utility>

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
