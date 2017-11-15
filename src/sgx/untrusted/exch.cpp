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

#include "Enclave_u.h"
#include "Utils.h"
#include "bitcoindrpcclient.h"
#include "tls_server_threaded_u.h"

#include "enclave_rpc.h"
#include <jsonrpccpp/server/connectors/httpserver.h>
#include "enclave_rpc.h"
#include "interrupt.h"

#include "config.h"

namespace po = boost::program_options;
namespace fs = boost::filesystem;

using namespace std;

#include <log4cxx/logger.h>
#include <log4cxx/propertyconfigurator.h>

namespace exch{
namespace main {
log4cxx::LoggerPtr logger(log4cxx::Logger::getLogger("exch.cpp"));
}
}

using exch::main::logger;
using exch::interrupt::init_signal_handler;

sgx_enclave_id_t eid;


static vector<uint8_t> readBinaryFile(const string &fname) {
  ifstream in(fname, std::ios::binary);
  if (!in.is_open()) {
    throw invalid_argument("cannot open file " + fname);
  }

  return vector<uint8_t>(istreambuf_iterator<char>(in),
                         istreambuf_iterator<char>());
}

static string readTextFile(const string &fname) {
  ifstream in(fname);
  if (!in.is_open()) {
    throw invalid_argument("cannot open file " + fname);
  }

  return string(istreambuf_iterator<char>(in), istreambuf_iterator<char>());
}


int main(int argc, const char *argv[]) {
  Config conf(argc, argv);

  init_signal_handler();

  log4cxx::PropertyConfigurator::configure(LOGGING_CONF);

  if (0 != initialize_enclave(&eid)) {
    cerr << "failed to init enclave" << endl;
    exit(-1);
  }

  sgx_status_t st;
  int ret = 0;

  int RPCSrvPort = 1234;
  bool RPCSrvRunning = false;
  jsonrpc::HttpServer httpserver(RPCSrvPort);
  EnclaveRPC enclaveRPC(eid, httpserver);
  if(enclaveRPC.StartListening()) {
    RPCSrvRunning = true;
    LOG4CXX_INFO(logger, "RPC server listening at localhost:" << RPCSrvPort);
  }

  try {
    LOG4CXX_INFO(logger, "launching " << conf.getIdentity());

    fs::path identity_dir(conf.getIdentity_dir());

    auto sealed_secret_path = (identity_dir / (conf.getIdentity() + ".priv"));
    auto cert_path = (identity_dir / (conf.getIdentity() + ".crt"));

    auto sealed = readBinaryFile(sealed_secret_path.string());
    auto cert = readTextFile(cert_path.string());

    st = provision_rsa_id(eid, &ret, sealed.data(), sealed.size(), cert.c_str());
    // die if failed to provision id
    if (st != SGX_SUCCESS || ret != 0) {
      cerr << "cannot provision rsa id. ret=" << ret << endl;
      exit(-1);
    }

    // print out the provisioned id
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


  thread fairnessProtocolServer;
  if (conf.getFairnessServerPort() > 0) {
    // prepare tls server
    auto port = conf.getFairnessServerPort();
    LOG4CXX_INFO(logger, "starting fairness server at " << port);
    fairnessProtocolServer = thread(TLSServerThreadPool("localhost", to_string(port), TLSServerThreadPool::FAIRNESS_SERVER, 5));
  }

  if (conf.getFairnessClientPort() > 0) {
    auto port = (unsigned int) conf.getFairnessClientPort();

    st = ssl_client_init(eid, &ret, "localhost", port);
    if (st != SGX_SUCCESS || ret != 0) {
      LOG4CXX_ERROR(logger, "cannot start fairness client");
      exit(-1);
    }
    LOG4CXX_INFO(logger, "fairness client started at " << port);

    st = ssl_client_write_test(eid, &ret);
    if (st != SGX_SUCCESS || ret != 0) {
      LOG4CXX_ERROR(logger, "ssl_client_write_test returns " << ret);
    }

    st = ssl_client_teardown(eid);
    if (st != SGX_SUCCESS) {
      LOG4CXX_ERROR(logger, "cannot teardown fairness client");
    }
  }

  if (fairnessProtocolServer.joinable()) {
    fairnessProtocolServer.join();
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

