//
// Created by lilione on 2017/11/6.
//
#include "state.h"



using namespace exch::enclave;

int ecall_eth_add_new_header(const char *_st) {
    try {
        std::string st(_st);
        Bytes bytes = Transform::hexStringToBytes(st);
        Header header = RLP::decodeHeader(bytes);
        if (state::server.queue.addNewHeader(header)) {
            LL_NOTICE("%s added", Transform::hashToHexString(header.blockHash).c_str());
            return 0;
        } else {
            LL_CRITICAL("failed to append block %s", Transform::hashToHexString(header.blockHash));
            return -1;
        }
    }
    catch (const std::exception &e) {
        LL_CRITICAL("exception in ecall: %s", e.what());
        return -1;
    }
}
