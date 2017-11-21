#include "state.h"

using namespace exch::enclave;

BlockFIFO<1000> state::blockFIFO;
BalanceBook state::balanceBook;

// SSL servers & clients
SSLServerContext* state::fairnessServerTrustedPart;
SSLServerContext* state::clientTLSServerTrustedPart;
TLSClient* state::tlsClient;
