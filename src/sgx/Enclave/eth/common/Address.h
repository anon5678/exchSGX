//
// Created by lilione on 2017/10/12.
//

#ifndef MERKLE_PARTRICIA_TREE_ADDRESS_H
#define MERKLE_PARTRICIA_TREE_ADDRESS_H

#include <cstdint>

using byte = uint8_t;

class Address {
public:
    byte data[20];

    bool operator!= (const Address & rhs) const {
        for (int i = 0; i < 20; i++) {
            if (data[i] != rhs.data[i]) return true;
        }
        return false;
    }

    bool operator== (const Address & rhs) const {
        for (int i = 0; i < 20; i++) {
            if (data[i] != rhs.data[i]) return false;
        }
        return true;
    }

    bool operator< (const Address & rhs) const {
        for (int i = 0; i < 20; i++) {
            if (data[i] < rhs.data[i]) return true;
            if (data[i] > rhs.data[i]) return false;
        }
        return false;
    }

    static void outputHex(Address);
};


#endif //MERKLE_PARTRICIA_TREE_ADDRESS_H
