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
#include "tls_service_pthread.h"

#include "enclave_rpc.h"
#include "interrupt.h"

namespace po = boost::program_options;
namespace fs = boost::filesystem;

using namespace std;

class Config {
 private:
  bool testBlockFeeding = false;
  string identity;
  string identity_dir;

  int fairnessServerPort;
  int fairnessClientPort;

 public:
  Config(int argc, const char* argv[]) {
    try {
      po::options_description desc("Allowed options");
      desc.add_options()
          ("help,h", "print this message")
          ("id,i", po::value(&this->identity)->required(), "dry run identity provision and exit.")
          ("id_dir", po::value(&this->identity_dir)->required(), "path to the dir where priv and crt files are stored.")
          ("feed,f", po::bool_switch(&this->testBlockFeeding)->default_value(false), "try to feed some blocks.")
          ("server,s", po::value(&this->fairnessServerPort)->default_value(-1), "run the fairness server at port [PORT].")
          ("client,c", po::value(&this->fairnessClientPort)->default_value(-1), "run the tls client at port [PORT]");

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

  int getFairnessServerPort() const {
    return this->fairnessServerPort;
  }

  int getFairnessClientPort() const {
    return fairnessClientPort;
  }

};

#endif //PROJECT_CONFIG_H
