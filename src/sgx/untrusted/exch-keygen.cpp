#include <sgx_error.h>
#include <boost/program_options.hpp>
#include <boost/algorithm/hex.hpp>

#include <fstream>
#include <iostream>
#include <string>

#include "Enclave_u.h"
#include "Utils.h"

#include "../common/errno.h"
#include "../common/base64.hxx"

using namespace std;
using namespace ext;

namespace po = boost::program_options;

#include "Utils.h"
#include <sgx_urts.h>

void print_key(sgx_enclave_id_t eid, const string& keyfile);
void keygen(sgx_enclave_id_t eid, const string& keyfile);

int main(int argc, const char *argv[]) {
  string key_input, key_output;
  string enclave_path;

  try {
    po::options_description desc("Allowed options");
    desc.add_options()("help,h", "print this message")(
        "enclave,e", po::value(&enclave_path)->required(), "which enclave to use?")(
        "print,p", po::value(&key_input), "print existing keys")(
        "keygen,g", po::value(&key_output), "generate a new key");

    po::variables_map vm;
    po::store(po::parse_command_line(argc, argv, desc), vm);

    if (vm.count("help")) {
      std::cerr << desc << endl;
      return -1;
    }
    po::notify(vm);
  } catch (po::required_option &e) {
    std::cerr << e.what() << endl;
    return -1;
  } catch (std::exception &e) {
    std::cerr << e.what() << endl;
    return -1;
  } catch (...) {
    std::cerr << "Unknown error!" << endl;
    return -1;
  }

  if ((key_input.empty() && key_output.empty()) ||
      (!key_input.empty() && !key_output.empty())) {
    std::cerr << "print specify exactly one command" << endl;
    std::exit(-1);
  }

  sgx_enclave_id_t eid;
  sgx_status_t st;
  int ret;

  ret = initialize_enclave(&eid);
  if (ret != 0) {
    cerr << "Failed to init the enclave" << endl;
    std::exit(-1);
  } else {
    cout << "enclave " << eid << " created" << endl;
  }

  if (!key_input.empty()) {
    print_key(eid, key_input);
  } else if (!key_output.empty()) {
    keygen(eid, key_output);
  }

  sgx_destroy_enclave(eid);
  cout << "Info: all enclave closed successfully." << endl;
}

#include "key_u.h"

void print_key(sgx_enclave_id_t eid, const string& keyfile) {
  cout << "printing key from " << keyfile << endl;
  ifstream in_keyfile(keyfile);
  if (!in_keyfile.is_open()) {
    cerr << "cannot open key file" << endl;
    exit(-1);
  }

  stringstream buffer;
  buffer << in_keyfile.rdbuf();

  cout << "Sealed Secret: " << buffer.str() << endl;

  string pubkey_b64 = unseal_key(eid, buffer.str(), exch::keyUtils::HYBRID_ENCRYPTION_KEY);
  cout << "PublicKey: " << pubkey_b64 << endl;
}

void keygen(sgx_enclave_id_t eid, const string& keyfile) {
  unsigned char secret_sealed[SECRETKEY_SEALED_LEN];
  unsigned char pubkey[PUBKEY_LEN];

  // call into enclave to fill the above buffers
  size_t buffer_used = 0;
  int ret = 0;
  sgx_status_t ecall_status = keygen_in_seal(eid, &ret, secret_sealed, &buffer_used, pubkey);
  if (ecall_status != SGX_SUCCESS || ret != 0) {
    cerr<< "ecall failed" << endl;
    print_error_message(ecall_status);
    cerr << "ecdsa_keygen_seal returns " << ret << endl;
    std::exit(-1);
  }

  string sealed_secret_b64 = ext::b64_encode(secret_sealed, sizeof secret_sealed);

  std::ofstream of(keyfile);
  if (!of.is_open()) {
    cerr << "cannot open key file: " << keyfile << endl;
    std::exit(-1);
  }
  of << sealed_secret_b64;
  of.close();

  cout << "Secret sealed to " << keyfile << endl;
  cout << "PublicKey: " << ext::b64_encode(pubkey, sizeof pubkey) << endl;
}

