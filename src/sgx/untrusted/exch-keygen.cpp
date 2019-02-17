#include <sgx_error.h>
#include <boost/algorithm/hex.hpp>
#include <boost/program_options.hpp>

#include <fstream>
#include <iostream>
#include <string>

#include "Enclave_u.h"
#include "Utils.h"

#include "../common/base64.hxx"
#include "../common/errno.h"

using namespace std;
using namespace ext;

namespace po = boost::program_options;

#include <sgx_urts.h>
#include "Utils.h"

void print_key(sgx_enclave_id_t eid, const string &keyfile);
void keygen(
    sgx_enclave_id_t eid, const string &keyfile, const string &subject_name);

sgx_enclave_id_t eid;

int main(int argc, const char *argv[])
{
  string key_input, key_output;
  string enclave_path;
  po::variables_map vm;

  try {
    po::options_description desc("Allowed options");
    desc.add_options()("help,h", "print this message");
    desc.add_options()(
        "enclave,e",
        po::value(&enclave_path)->required(),
        "which enclave to use?");
    desc.add_options()("print,p", po::value(&key_input), "print existing keys");
    desc.add_options()(
        "keygen,g", po::value(&key_output), "generate a new key");
    desc.add_options()(
        "subject,s",
        po::value<string>()->default_value("C=US,O=exch,CN=exch-encalve-1"),
        "subject name (used in cert)");

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

  int ret;

  ret = initialize_enclave(enclave_path, &eid);
  if (ret != 0) {
    cerr << "Failed to init the enclave" << endl;
    std::exit(-1);
  } else {
    cout << "enclave " << eid << " created" << endl;
  }

  if (!key_input.empty()) {
    print_key(eid, key_input);
  } else if (!key_output.empty()) {
    keygen(eid, key_output, vm["subject"].as<string>());
  }

  sgx_destroy_enclave(eid);
  cout << "Info: all enclave closed successfully." << endl;
}

void print_key(sgx_enclave_id_t eid, const string &keyfile)
{
  cout << "NOT IMPLEMENTED YET" << endl;
}

void keygen(
    sgx_enclave_id_t eid, const string &keyfile, const string &subject_name)
{
  cout << "using subject name " << subject_name << endl;

  unsigned char secret_sealed[5000];
  unsigned char pubkey[NACL_PUBLICKEY_SIZE];

  // call into enclave to fill the above buffers
  size_t buffer_used = 0;
  sgx_status_t ecall_status = nacl_keygen_in_seal(
      eid, &buffer_used, secret_sealed, sizeof secret_sealed, pubkey);
  if (ecall_status != SGX_SUCCESS || buffer_used < 0) {
    cerr << "ecall failed" << endl;
    print_error_message(ecall_status);
    cerr << "rsa_keygen_in_seal returns " << buffer_used << endl;
    std::exit(-1);
  }

  string privkey_fn = keyfile + ".priv";
  ofstream of(privkey_fn, std::ios::binary);
  of.write((char *)secret_sealed, buffer_used);
  of.close();

  cout << "secret sealed to " << privkey_fn << endl;

  // write the public key
  string pubkey_fn = keyfile + ".pub";
  of.open(pubkey_fn);
  of << pubkey;
  of.close();

  cout << "public key dumped to " << pubkey_fn << endl;
}
