//
// Created by fanz on 7/11/17.
//

#include "bitcoindrpcclient.h"
#include "Enclave_u.h"
#include "jsonrpccpp/client/connectors/httpclient.h"
#include "Utils.h"
#include "tls_server_threaded.h"
#include "blockfeeding.h"

#include <sgx_urts.h>

#include <iostream>
#include <memory>
#include <csignal>
#include <atomic>
#include <thread>

#include <boost/program_options.hpp>

namespace po = boost::program_options;

using namespace std;

sgx_enclave_id_t eid;

class Config {
 public:
  bool testBlockFeeding = false;
  bool runServer = false;
  bool runClient = false;
};
void config(int argc, const char* argv[], Config& conf);


int main(int argc, const char* argv[]) {
  Config conf;
  config(argc, argv, conf);

  if (0 != initialize_enclave(&eid)) {
    cerr << "failed to init enclave" << endl;
    exit(-1);
  }

  int ret;

  if (conf.runServer) {
    // prepare tls server
    tls_server_init(4433);
  }
  else if (conf.runClient) {
    test_tls_client(eid, &ret, "localhost", 4433);
  }
  else if (conf.testBlockFeeding) {
    test_feed_blocks();
  }

  sgx_destroy_enclave(eid);
}

void config(int argc, const char* argv[], Config& config) {
  try {
    po::options_description desc("Allowed options");
    desc.add_options()
        ("help,h", "print this message")
        ("feed,f", po::bool_switch(&config.testBlockFeeding)->default_value(false), "try to feed some blocks")
        ("server,s", po::bool_switch(&config.runServer)->default_value(false), "run as a tls server")
        ("client,c", po::bool_switch(&config.runClient)->default_value(false), "run as a tls client");

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
