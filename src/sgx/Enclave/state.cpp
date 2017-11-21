#include "state.h"

using namespace exch::enclave;

BlockFIFO<1000> state::blockFIFO;
BalanceBook state::balanceBook;

// SSL servers & clients
SSLContextManager* state::fairnessServerTrustedPart;
SSLContextManager* state::clientTLSServerTrustedPart;
TLSClient* state::tlsClient;
