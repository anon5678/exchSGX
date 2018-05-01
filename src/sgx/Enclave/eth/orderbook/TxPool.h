//
// Created by lilione on 2018/4/9.
//

#ifndef EXCHSGX_COPY_TXPOOL_H
#define EXCHSGX_COPY_TXPOOL_H

#endif //EXCHSGX_COPY_TXPOOL_H

#include <vector>

#include "Tx.h"

class TxPool {
public:
    std::vector<Tx> pool;

    void add(Tx);
};