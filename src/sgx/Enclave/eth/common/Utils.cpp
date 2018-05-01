//
// Created by lilione on 2017/9/21.
//

#include <cstdio>
#include <vector>
#include <sstream>

#include "Utils.h"
#include "Transform.h"

bool Utils::equal(ethash_h256_t x, ethash_h256_t y) {
    for (int i = 0; i < 32; i++) {
        if (x.b[i] != y.b[i]) {
            //printf("%d\n", i);
            return false;
        }
    };
    return true;
};

uint256_t Utils::power(uint256_t x, uint256_t y) {
    uint256_t ret = 1, z = x;
    while (y) {
        if (y & 1) ret *= z;
        z *= z;
        y >>= 1;
    }
    return ret;
}

uint256_t Utils::min(uint256_t x, uint256_t y) {
    return (x < y) ? x : y;
}

uint256_t Utils::max(uint256_t x, uint256_t y) {
    return (x > y) ? x : y;
}

/*Bytes Utils::readHexString() {
    char st[1000000];
    gets(st);
    std::string ret = "";
    for (int i = 0; i < strlen(st); i++) {
        if (st[i] != ' ') ret += st[i];
    }
    return Transform::hexStringToBytes(ret);
}*/

/*void Utils::outputHex(ethash_h256_t hash) {
    for (int i = 0; i < 32; i++) {
        printf("%02x", hash.b[i]);
    }
    printf("\n");
}*/

bool Utils::check_ethash_h256_(ethash_h256_t x) {
    for (int i = 0; i < 32; i++) {
        if (x.b[i] != 0) return false;
    }
    return true;
}