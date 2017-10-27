//
// Created by fanz on 9/21/17.
//

#include "state.h"

using namespace exch::enclave;

BlockFIFO<1000> state::blockFIFO;
BalanceBook state::balanceBook;
TLSConnectionHandler* state::connectionHandler;
TLSClient* state::tlsClient;
