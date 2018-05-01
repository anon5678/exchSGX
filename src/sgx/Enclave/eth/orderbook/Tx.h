//
// Created by lilione on 2018/4/9.
//

#ifndef EXCHSGX_COPY_TX_H
#define EXCHSGX_COPY_TX_H

#endif //EXCHSGX_COPY_TX_H

#include "../common/Address.h"
#include "../common/uint256_t.h"

typedef uint256_t VolumeType;

class Tx {
public:
    Address from, to;
    VolumeType volume;

    Tx(Address from, Address to, VolumeType volume) :
            from(from), to(to), volume(volume) {}
};
