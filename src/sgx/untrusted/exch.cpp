#include <sgx_urts.h>
#include <stdexcept>
#include <atomic>
#include <csignal>
#include <fstream>
#include <iostream>
#include <memory>
#include <thread>

#include <boost/program_options.hpp>
#include <boost/algorithm/hex.hpp>
#include <jsonrpccpp/client/connectors/httpclient.h>

#include "Enclave_u.h"
#include "Utils.h"
#include "bitcoindrpcclient.h"
#include "blockfeeding.h"
#include "tls_server_threaded.h"

#include "enclaverpc.h"

namespace po = boost::program_options;

using namespace std;

sgx_enclave_id_t eid;

class Config {
public:
  bool testBlockFeeding = false;
  bool runServer = false;
  bool runClient = false;
  string rsa_secret_key = "";
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

#include <jsonrpccpp/server/connectors/httpserver.h>
#include "enclaverpc.h"

int main(int argc, const char *argv[]) {
  Config conf;
  config(argc, argv, conf);

  if (0 != initialize_enclave(&eid)) {
    cerr << "failed to init enclave" << endl;
    exit(-1);
  }

  sgx_status_t st;
  int ret = 0;

  jsonrpc::HttpServer httpserver(1234);
  EnclaveRPC enclaveRPC(eid, httpserver);

  enclaveRPC.StartListening();
  getchar();
  enclaveRPC.StopListening();

  if (!conf.rsa_secret_key.empty()) {
    try {
      cout << "provisioning RSA key from " << conf.rsa_secret_key << "..."
           << endl;
      auto sealed = readBinaryFile(conf.rsa_secret_key);
      st = provision_rsa_id(eid, &ret, sealed.data(), sealed.size());
      if (st != SGX_SUCCESS || ret != 0) {
        cerr << "cannot provision rsa id. ret=" << ret << endl;
      } else {
        unsigned char pubkey[1024];
        st = query_rsa_pubkey(eid, &ret, pubkey, sizeof pubkey);
        if (st != SGX_SUCCESS || ret != 0) {
          cerr << "cannot query rsa id. ret=" << ret << endl;
        }
        cout << "using the following public key..." << endl;
        cout << (char *)pubkey;
      }

    } catch (const std::exception &e) {
      cerr << "cannot provision rsa id: " << e.what() << endl;
    }
  }

  if (conf.runServer) {
    // prepare tls server
    tls_server_init(4433);
  } else if (conf.runClient) {
    test_tls_client(eid, &ret, "localhost", 4433);
  } else if (conf.testBlockFeeding) {
    test_feed_blocks();
  }

  sgx_destroy_enclave(eid);
}

void config(int argc, const char *argv[], Config &config) {
  try {
    po::options_description desc("Allowed options");
    desc.add_options()
        ("help,h", "print this message")
        ("id,i", po::value<string>(&config.rsa_secret_key)->default_value(""), "dry run identity provision and exit.")
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
