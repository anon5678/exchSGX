//
// Created by lilione on 2017/8/31.
//

#ifndef MERKLE_PARTRICIA_TREE_BYTEARRAY_H
#define MERKLE_PARTRICIA_TREE_BYTEARRAY_H

#include <cstdint>
#include <vector>
#include <cstring>

#include "../libethash/ethash.h"

using byte = uint8_t;

class Bytes {
public:
    std::vector<byte> data;

    Bytes() {}

    Bytes(byte);

    Bytes operator+ (const Bytes&);

    bool operator== (const Bytes&);

    bool operator!= (const Bytes&);

    void operator= (const Bytes&);

    Bytes substr(int, int);
    Bytes substr(int);

    static void output(Bytes);
    static void outputHex(Bytes);
};


#endif //MERKLE_PARTRICIA_TREE_BYTEARRAY_H
