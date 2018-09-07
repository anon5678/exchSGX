//
// Created by lilione on 2017/10/9.
//

#ifndef POW_QUEUE_H
#define POW_QUEUE_H

#include <deque>

#include "Header.h"

class Queue {
public:
    const unsigned int QUEUE_LENGTH = 50;
    const unsigned int COMFIRM_TIME = 6;

    std::deque<Header> headers;

    bool addNewHeader(const Header& header);
    Header getHeader(uint256_t);
    ethash_h256_t getReceiptRoot(uint256_t);
    ethash_h256_t getStateRoot(uint256_t);
    uint256_t getNewestBlockNumber();//newest confirmed blockNumber
};


#endif //POW_QUEUE_H
