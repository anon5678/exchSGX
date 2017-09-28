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
#include "tls_service_pthread.h"

#include "enclave_rpc.h"
#include <jsonrpccpp/server/connectors/httpserver.h>
#include "enclave_rpc.h"
#include "interrupt.h"

namespace po = boost::program_options;
namespace fs = boost::filesystem;

using namespace std;

#include <log4cxx/logger.h>
#include <log4cxx/propertyconfigurator.h>

namespace exch{
namespace main {
log4cxx::LoggerPtr logger(log4cxx::Logger::getLogger("exch.main"));
}
}

using exch::main::logger;
using exch::interrupt::init_signal_handler;

sgx_enclave_id_t eid;

class Config {
public:
  bool testBlockFeeding = false;
  bool runServer = false;
  bool runClient = false;
  string identity;
  string identity_dir;
};

void config(int argc, const char *argv[], Config &conf);


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
  Config conf;
  config(argc, argv, conf);

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
    LOG4CXX_INFO(logger, "using id " << conf.identity);

    fs::path identity_dir(conf.identity_dir);

    auto sealed_secret_path = (identity_dir / (conf.identity + ".priv"));
    auto cert_path = (identity_dir / (conf.identity + ".crt"));

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

    LOG4CXX_INFO(logger, "RSA secret key for " << conf.identity << " provisioned");

    // cout << "using the following public key..." << endl;
    // cout << (char *)pubkey;
    // cout << cert_pem;
  } catch (const std::exception &e) {
    cerr << "cannot provision rsa id: " << e.what() << endl;
    exit(-1);
  }


  thread fairnessProtocolServer;
  if (conf.runServer) {
    // prepare tls server
    fairnessProtocolServer = thread(TLSService("localhost", "4433", TLSService::FAIRNESS_SERVER, 5));
  } else if (conf.runClient) {
    test_tls_client(eid, &ret, "localhost", 4433);
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

void config(int argc, const char *argv[], Config &config) {
  try {
    po::options_description desc("Allowed options");
    desc.add_options()
        ("help,h", "print this message")
        ("id,i", po::value(&config.identity)->required(), "dry run identity provision and exit.")
        ("id_dir", po::value(&config.identity_dir)->required(), "path to the dir where priv and crt files are stored.")
        ("feed,f", po::bool_switch(&config.testBlockFeeding)->default_value(false), "try to feed some blocks.")
        ("server,s", po::bool_switch(&config.runServer)->default_value(false), "run as a tls server.")
        ("client,c", po::bool_switch(&config.runClient)->default_value(false), "run as a tls client.");

    po::variables_map vm;
    po::store(po::parse_command_line(argc, argv, desc), vm);

    if (vm.count("help")) {
      cerr << desc << endl;
      exit(0);
    }
    po::notify(vm);
  } catch (po::required_option &e) {
    cerr << e.what() << endl;
    exit(-1);
  } catch (std::exception &e) {
    cerr << e.what() << endl;
    exit(-1);
  } catch (...) {
    cerr << "Unknown error!" << endl;
    exit(-1);
  }
}
