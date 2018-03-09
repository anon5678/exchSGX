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
#include <jsonrpccpp/client/connectors/httpclient.h>
#include <jsonrpccpp/server/connectors/httpserver.h>
#include <log4cxx/logger.h>
#include <log4cxx/propertyconfigurator.h>

#include "bitcoindrpcclient.h"
#include "tls_server_threaded_u.h"
#include "enclave_rpc.h"
#include "interrupt.h"
#include "config.h"
#include "Utils.h"

#include "Enclave_u.h"

namespace po = boost::program_options;
namespace fs = boost::filesystem;

using namespace std;


namespace exch{
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

  // try to load sealed secret keys
  try {
    LOG4CXX_INFO(logger, "launching " << conf.getIdentity());

    fs::path identity_dir(conf.getIdentity_dir());

    auto sealed_secret_path = (identity_dir / (conf.getIdentity() + ".priv"));
    auto cert_path = (identity_dir / (conf.getIdentity() + ".crt"));

    auto sealed = readBinaryFile(sealed_secret_path.string());
    auto cert = readTextFile(cert_path.string());

    // provision the sealed RSA key. Die if this fails.
    st = provision_rsa_id(eid, &ret, sealed.data(), sealed.size(), cert.c_str());
    if (st != SGX_SUCCESS || ret != 0) {
      cerr << "cannot provision rsa id. ret=" << ret << endl;
      exit(-1);
    }

    // ask enclave for the public key corresponding to the provisioned secret key
    unsigned char pubkey[1024];
    char cert_pem[2048];
    st = query_rsa_pubkey(eid, &ret, pubkey, sizeof pubkey, cert_pem, sizeof cert_pem);
    if (st != SGX_SUCCESS || ret != 0) {
      cerr << "error in provisioning the id" << ret << endl;
      exit(-1);
    }

    LOG4CXX_INFO(logger, "RSA secret key for " << conf.getIdentity() << " provisioned");
  } catch (const std::exception &e) {
    cerr << "cannot provision rsa id: " << e.what() << endl;
    exit(-1);
  }

  // start a RPC server (defined in enclave_rpc.cpp)
  int RPCSrvPort = 1234;
  bool RPCSrvRunning = false;
  jsonrpc::HttpServer httpserver(RPCSrvPort);
  EnclaveRPC enclaveRPC(eid, httpserver);
  if(enclaveRPC.StartListening()) {
    RPCSrvRunning = true;
    LOG4CXX_INFO(logger, "RPC server listening at localhost:" << RPCSrvPort);
  }

  while(!exch::interrupt::quit.load())
  {
    this_thread::sleep_for(chrono::seconds(2));
  }

  if (RPCSrvRunning)
  {
    enclaveRPC.StopListening();
    LOG4CXX_INFO(logger, "shutting down the RPC server...")
  }

  sgx_destroy_enclave(eid);
}

