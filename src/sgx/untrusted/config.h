#ifndef PROJECT_CONFIG_H
#define PROJECT_CONFIG_H

#include <iostream>
#include <fstream>
#include <string>
#include <boost/program_options.hpp>
#include <boost/algorithm/hex.hpp>
#include <boost/filesystem.hpp>
#include <jsonrpccpp/client/connectors/httpclient.h>
#include <jsonrpccpp/server/connectors/httpserver.h>

#include "Enclave_u.h"
#include "Utils.h"
#include "bitcoindrpcclient.h"

#include "enclave-rpc-server-impl.h"
#include "interrupt.h"
#include "external/toml.h"

namespace po = boost::program_options;
namespace fs = boost::filesystem;

using namespace std;

class Config {
private:
  string identity;
  string identity_dir;
  bool is_fairness_leader;
  string config_file;
  string leader_addr;
  vector<string> follower_addr_list;

public:
  Config(int argc, const char *argv[]) {
    try {
      po::options_description desc("Allowed options");
      desc.add_options()
          ("help,h", "print this message")
          ("c,config", po::value(&config_file)->default_value("config.toml"), "config file")
          ("l,leader", po::bool_switch(&is_fairness_leader)->default_value(false), "work as the fairness leader");

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

    ifstream conf_ifs(config_file);
    toml::ParseResult pr = toml::parse(conf_ifs);

    if (!pr.valid()) {
      cerr << pr.errorReason << endl;
      exit(-1);
    }

    try {
      const toml::Value& v = pr.value;
      leader_addr = v.get<string>("fairness.leader");
      follower_addr_list = v.get<vector<string>>("fairness.followers");
    }
    catch (const exception& e) {
      cerr << "invalid config file: " << e.what() << endl;
      exit(-1);
    }
  }

  const string &getIdentity() const {
    return identity;
  }
  const string &getIdentity_dir() const {
    return identity_dir;
  }
  bool getIsFairnessLeader() const { return is_fairness_leader; }

  const string &getLeaderAddr() const {
    return leader_addr;
  }
  const vector<string> &getFollowerAddrList() const {
    return follower_addr_list;
  }
};

#endif //PROJECT_CONFIG_H
