#include "bitcoindrpcclient.h"
#include "Utils.h"
#include "Enclave_u.h"

#include <iostream>

using namespace std;

int main() {
  sgx_enclave_id_t eid;

  if (0 != initialize_enclave(&eid)) {
    cerr << "failed to init enclave" << endl;
    exit(-1);
  }

  int ret;
  std::cout << "starting tests" << endl;

  enclaveTest(eid, &ret);
}