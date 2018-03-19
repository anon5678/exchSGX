//
// Created by fanz on 10/26/17.
//

#ifndef PROJECT_CONFIG_H
#define PROJECT_CONFIG_H

#include <iostream>
#include <boost/program_options.hpp>
#include <boost/algorithm/hex.hpp>
#include <boost/filesystem.hpp>
#include <jsonrpccpp/client/connectors/httpclient.h>
#include <jsonrpccpp/server/connectors/httpserver.h>

#include "Enclave_u.h"
#include "Utils.h"
#include "bitcoindrpcclient.h"
#include "tls_server_threaded_u.h"

#include "enclave-rpc-server-impl.h"
#include "interrupt.h"

namespace po = boost::program_options;
namespace fs = boost::filesystem;

using namespace std;

class Config {
private:
  bool testBlockFeeding = false;
  string identity;
  string identity_dir;
  uint16_t rpcServerPort;
  bool fairnessLeader;

public:
  Config(int argc, const char *argv[]) {
    try {
      po::options_description desc("Allowed options");
      desc.add_options()
          ("help,h", "print this message")
          ("p,port", po::value(&rpcServerPort)->required(), "RPC Port")
          ("l,leader", po::bool_switch(&fairnessLeader)->default_value(false), "work as the fairness leader")
          ("feed,f", po::bool_switch(&testBlockFeeding)->default_value(false), "try to feed some blocks.");

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

  bool isTestBlockFeeding() const {
    return testBlockFeeding;
  }

  const string &getIdentity() const {
    return identity;
  }
  const string &getIdentity_dir() const {
    return identity_dir;
  }
  uint16_t getRpcPort() const {
    return rpcServerPort;
  }
  bool getIsFairnessLeader() const { return fairnessLeader; }
};

#endif //PROJECT_CONFIG_H
