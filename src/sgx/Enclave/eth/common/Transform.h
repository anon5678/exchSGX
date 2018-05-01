//
// Created by lilione on 2017/10/11.
//

#ifndef MERKLE_PARTRICIA_TREE_TRANSFORM_H
#define MERKLE_PARTRICIA_TREE_TRANSFORM_H


#include "Bytes.h"
#include "uint256_t.h"
#include "Address.h"

class Transform {
public:

    static int fromHex(char);
    static char toHex(int);

    static Bytes stringToBytes(std::string);

    static Bytes hexStringToBytes(std::string);
    static ethash_h256_t hexStringToHash(std::string);
    static uint256_t hexStringToUint256(std::string);

    static std::string bytesToString(Bytes);
    static std::string bytesToHexString(Bytes);
    static ethash_h256_t bytesToHash(Bytes);
    static Address bytesToAddr(Bytes);
    static uint256_t bytesToUint256(Bytes);
    static uint64_t bytesToUint64(Bytes);
    static unsigned int bytesToUint(Bytes);

    static Bytes hashToBytes(ethash_h256_t);
    static std::string hashToHexString(ethash_h256_t);

    static Bytes addrToBytes(Address);

    static uint256_t intStringToUint256(std::string);

    static ethash_h256_t uint256ToHash(uint256_t);
    static Bytes uint256ToBytes(uint256_t);

    static Bytes intToBytes(int);

    static Bytes uint64ToBytes(uint64_t);

};


#endif //MERKLE_PARTRICIA_TREE_TRANSFORM_H
