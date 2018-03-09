#include "state.h"

using namespace exch::enclave;

BlockFIFO<1000> state::blockFIFO;
BalanceBook state::balanceBook;

// SSL servers & clients
TLSClient* state::tlsClient;
