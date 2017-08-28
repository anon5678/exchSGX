//
// Created by fanz on 7/11/17.
//

#include "bitcoindrpcclient.h"
#include "Enclave_u.h"
#include "jsonrpccpp/client/connectors/httpclient.h"
#include "Utils.h"
#include "tls_server_threaded.h"

#include <sgx_urts.h>

#include <iostream>
#include <memory>
#include <csignal>
#include <atomic>
#include <thread>

#include <boost/program_options.hpp>

namespace po = boost::program_options;

using namespace std;

namespace cfg {
string bitcoind_rpc_addr = "http://exch:goodpass@localhost:8332";
}

string get_blockheader_hex(bitcoindRPCClient &rpc, uint32_t height) {
  string hash = rpc.getblockhash(height);
  Json::Value hdr = rpc.getblockheader(hash, false); // false for binary format
  return hdr.asString();
}

bool push_one(sgx_enclave_id_t eid, bitcoindRPCClient &rpc, int blocknum) {
  try {
    string hdr_hex = get_blockheader_hex(rpc, blocknum);
    appendBlockToFIFO(eid, hdr_hex.c_str());
    return true;
  }
  catch (const jsonrpc::JsonRpcException &e) {
    cerr << "JSONRPC error: " << e.what();
  }
  catch (const exception &e) {
    cerr << "std exception catched: " << e.what() << endl;
  }
  catch (...) {
    cerr << "unknown err" << endl;
  }

  return false;
}

int test_feed_blocks() {
  // note that bitcoin uses JSON-RPC 1.0
  jsonrpc::HttpClient connector(::cfg::bitcoind_rpc_addr);
  bitcoindRPCClient rpc(connector, jsonrpc::JSONRPC_CLIENT_V1);

  sgx_enclave_id_t eid;

  if (0 != initialize_enclave(&eid)) {
    cerr << "failed to init enclave" << endl;
    exit(-1);
  }

  int test_block_1[3] {10000, 10001, 10002};
  int test_block_2[4] {10003, 10004, 10005, 10007};


  cout << "Testing one. Suppose to succeed\n";
  cout << "===============================" << endl;

  for (auto b : test_block_1) {
    push_one(eid, rpc, b);
  }

  cout << endl;
  cout << "Testing two. Suppose to fail on the last one\n";
  cout << "============================================" << endl;

  for (auto b : test_block_2) {
    push_one(eid, rpc, b);
  }

  return 0;
}

sgx_enclave_id_t eid;

class Config {
 public:
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

  sgx_destroy_enclave(eid);
}




void config(int argc, const char* argv[], Config& config) {
  try {
    po::options_description desc("Allowed options");
    desc.add_options()
        ("help,h", "print this message")
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
