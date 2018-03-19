#include "enclave-rpc-client-impl.h"
#include "Enclave_u.h"

using exch::rpc::Client;
using namespace std;

// ecall
void sendMessagesToFairnessFollower(const char* host, int port, const unsigned char* msg, size_t size) {
  try {
    Client c(host, port);
    c.distributeSettlementPkg(msg, size);
  }
  catch (const exception& e) {
    cerr << e.what() << endl;
  }
  catch (...) {
    cerr << "Error happened" << endl;
    return;
  }
}

void sendAckToFairnessLeader(const char* host, int port, const unsigned char* msg, size_t size) {
  try {
    Client c(host, port);
    c.ackSettlementPkg();
  }
  catch (const exception& e) {
    cerr << e.what() << endl;
  }
  catch (...) {
    cerr << "Error happened" << endl;
    return;
  }
}
