//
// Created by lilione on 8/30/18.
//

#include "state.h"

using namespace exch::enclave;

int eth_receiveOrder(const char* st) {
    try {
        state::server.receiveOrder(st);
    }
    catch (const std::exception &e) {
        LL_CRITICAL("exception in ecall: %s", e.what());
        return -1;
    }
}

int eth_receiveWithdraw(const char* st) {
    try {
        state::server.receiveWithdraw(st);
    }
    catch (const std::exception &e) {
        LL_CRITICAL("exception in ecall: %s", e.what());
        return -1;
    }
}

int eth_proofsVerify(const char* st) {
    try {
        state::server.proofsVerify(st);
    }
    catch (const std::exception &e) {
        LL_CRITICAL("exception in ecall: %s", e.what());
        return -1;
    }
}

int eth_receiveHeaders(const char* st) {
    try {
        state::server.receiveHeaders(st);
    }
    catch (const std::exception &e) {
        LL_CRITICAL("exception in ecall: %s", e.what());
        return -1;
    }
}