#include <sgx_urts.h>
#include <stdexcept>
#include <atomic>
#include <csignal>
#include <fstream>
#include <iostream>
#include <memory>
#include <thread>
#include <chrono>

#include <boost/program_options.hpp>
#include <boost/algorithm/hex.hpp>
#include <boost/filesystem.hpp>
#include <boost/asio/io_service.hpp>
#include <boost/asio/deadline_timer.hpp>
#include <boost/thread/thread.hpp>

#include <jsonrpccpp/server.h>
#include <jsonrpccpp/client/connectors/httpclient.h>
#include <jsonrpccpp/server/connectors/httpserver.h>
#include <log4cxx/logger.h>
#include <log4cxx/propertyconfigurator.h>

#include "bitcoind-merkleproof.h"
#include "bitcoindrpcclient.h"
#include "enclave-rpc-server-impl.h"
#include "interrupt.h"
#include "config.h"
#include "Utils.h"
#include "Enclave_u.h"
#include "external/toml.h"

namespace po = boost::program_options;
namespace fs = boost::filesystem;
namespace aio = boost::asio;

using namespace std;

namespace exch {
namespace main {
log4cxx::LoggerPtr logger(log4cxx::Logger::getLogger("exch.cpp"));
}
}

using exch::main::logger;

sgx_enclave_id_t eid;

int main(int argc, const char *argv[]) {
  // initialize logging and stuff
  Config conf(argc, argv);
  log4cxx::PropertyConfigurator::configure(LOGGING_CONF);
  exch::interrupt::init_signal_handler();

  // try to create an enclave
  if (0 != initialize_enclave(&eid)) {
    cerr << "failed to init enclave" << endl;
    exit(-1);
  }

  sgx_status_t st;
  int ret = 0;

  // call the function at Enclave/enclave_test.cpp:55
  st = enclaveTest(eid, &ret);
  if (st != SGX_SUCCESS) {
    LOG4CXX_ERROR(logger, "ecall failed with return value " << st);
  }

  // destroy the enclave last
  sgx_destroy_enclave(eid);
}

