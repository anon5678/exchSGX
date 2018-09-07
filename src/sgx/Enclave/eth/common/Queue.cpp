//
// Created by lilione on 2017/10/9.
//

#include "Queue.h"

bool Queue::addNewHeader(const Header& header) {
    if (headers.empty() || Header::check(header, headers.back())) {
        while (headers.size() >= QUEUE_LENGTH) {
            headers.pop_front();
        }
        headers.push_back(header);
        return true;
    }
    return false;
}

Header Queue::getHeader(uint256_t blockNumber) {
    Header newestHeader = headers.back();
    if (newestHeader.number - blockNumber < COMFIRM_TIME) {
        return Header();
    }
    std::deque<Header>::iterator iter = std::find(headers.begin(), headers.end(), Header(blockNumber));
    if (iter != headers.end()) {
        return (Header)(*iter);
    }
    return Header();
}

ethash_h256_t Queue::getReceiptRoot(uint256_t blockNumber) {
    Header header = getHeader(blockNumber);
    if (!header.number) {
        return ethash_h256_t();
    }
    return header.receiptRoot;
}

ethash_h256_t Queue::getStateRoot(uint256_t blockNumber) {
    Header header = getHeader(blockNumber);
    if (!header.number) {
        return ethash_h256_t();
    }
    return header.stateRoot;
}

uint256_t Queue::getNewestBlockNumber() {
    return headers.back().number - COMFIRM_TIME;
}