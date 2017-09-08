#include <boost/algorithm/hex.hpp>
#include <boost/program_options.hpp>
#include <sgx_error.h>

#include <fstream>
#include <iostream>
#include <string>

#include "Enclave_u.h"
#include "key_u.h"
#include "Utils.h"

#include "../common/base64.hxx"
#include "../common/errno.h"

using namespace std;
using namespace ext;

namespace po = boost::program_options;

#include "Utils.h"
#include <sgx_urts.h>

void print_key(sgx_enclave_id_t eid, const string &keyfile);
void keygen(sgx_enclave_id_t eid, const string &keyfile);

int main(int argc, const char *argv[]) {
  string key_input, key_output;
  string enclave_path;

  try {
    po::options_description desc("Allowed options");
    desc.add_options()("help,h", "print this message")(
        "enclave,e", po::value(&enclave_path)->required(),
        "which enclave to use?")("print,p", po::value(&key_input),
                                 "print existing keys")(
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


void print_key(sgx_enclave_id_t eid, const string &keyfile) {
  cout << "printing key from " << keyfile << endl;
  ifstream in_keyfile(keyfile, std::ios::binary);
  if (!in_keyfile.is_open()) {
    cerr << "cannot open key file" << endl;
    exit(-1);
  }

  vector<unsigned char> sealed_secret((istreambuf_iterator<char>(in_keyfile)),
                                      istreambuf_iterator<char>());

  string pubkey_pem =
      unseal_key(eid, sealed_secret, exch::keyUtils::HYBRID_ENCRYPTION_KEY);
  cout << "PublicKey: \n" << pubkey_pem;
}

void keygen(sgx_enclave_id_t eid, const string &keyfile) {
  unsigned char secret_sealed[5000];
  unsigned char pubkey[1000];

  // call into enclave to fill the above buffers
  int buffer_used = 0;
  sgx_status_t ecall_status =
      rsa_keygen_in_seal(eid, &buffer_used, secret_sealed, sizeof secret_sealed,
                         pubkey, sizeof pubkey);
  if (ecall_status != SGX_SUCCESS || buffer_used < 0) {
    cerr << "ecall failed" << endl;
    print_error_message(ecall_status);
    cerr << "rsa_keygen_in_seal returns " << buffer_used << endl;
    std::exit(-1);
  }

  cout << "sealed secret has " << buffer_used << " bytes" << endl;

  std::ofstream of(keyfile, std::ios::binary);
  if (!of.is_open()) {
    cerr << "cannot open key file: " << keyfile << endl;
    std::exit(-1);
  }
  of.write((char *)secret_sealed, buffer_used);
  ;
  of.close();

  cout << "secret sealed to " << keyfile << endl;
  cout << "PublicKey: \n" << pubkey;
}
