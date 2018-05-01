//
// Created by lilione on 2017/10/11.
//

#include <string>
#include <sstream>

#include "Transform.h"

int Transform::fromHex(char _i) {
    if (isdigit(_i))
        return _i - '0';
    if (islower(_i))
        return _i - 'a' + 10;
    if (isupper(_i))
        return _i - 'A' + 10;

    //static_assert("should never get here");
    return -1;
}

char Transform::toHex(int _i) {
    if (_i < 10) return _i + '0';
    if (_i < 16) return _i - 10 + 'a';

    //static_assert("should never get here");
    return -1;
}

Bytes Transform::stringToBytes(std::string st) {
    Bytes ret;
    for (int i = 0; i < st.length(); i++) {
        ret.data.push_back(uint8_t(st[i]));
    }
    return ret;
}

Bytes Transform::hexStringToBytes(std::string st) {
    unsigned int pos = (st[0] == '0' && st[1] == 'x') ? 2 : 0;
    Bytes ret;
    ret.data.reserve((st.size() - pos + 1) / 2);

    if (st.size() % 2) {
        ret.data.push_back(fromHex(st[pos++]));
    }
    for (unsigned int i = pos; i < st.size(); i += 2) {
        ret.data.push_back((byte)(fromHex(st[i]) * 16 + fromHex(st[i + 1])));
    }

    return ret;
}

ethash_h256_t Transform::hexStringToHash(std::string st) {
    ethash_h256_t ret;
    Bytes b = hexStringToBytes(st);
    memcpy(&ret, b.data.data(), b.data.size());
    return ret;
}

uint256_t Transform::hexStringToUint256(std::string st) {
    uint256_t ret = 0;

    if (st[0] == '0' && st[1] == 'x') {
        st = st.substr(2);
    }

    for (int i = 0; i < st.length(); i++) {
        ret = ret * 16 + fromHex(st[i]);
    }

    return ret;
}

std::string Transform::bytesToString(Bytes bytes) {
    std::string st;
    for (int i = 0; i < bytes.data.size(); i++) {
        st += char(bytes.data[i]);
    }
    return st;
}

std::string Transform::bytesToHexString(Bytes array) {
    std::string ret;
    for (int i = 0; i < array.data.size(); i++) {
        int now = array.data[i];
        ret += toHex(now / 16);
        ret += toHex(now % 16);
    }
    return ret;
}

ethash_h256_t Transform::bytesToHash(Bytes bytes) {
    ethash_h256_t ret;
    if (bytes.data.size() <= 32) {
        int i = 0;
        for ( ; i < bytes.data.size(); i++) {
            ret.b[i] = bytes.data[i];
        }
        for ( ; i < 32; i++) {
            ret.b[i] = 0;
        }
        return ret;
    }
    //static_assert("Invalid Transformation!\n");
}

Address Transform::bytesToAddr(Bytes bytes) {
    Address ret;
    if (bytes.data.size() >= 20) {
        bytes = bytes.substr(bytes.data.size() - 20);
        int i = 0;
        for ( ; i < bytes.data.size(); i++) {
            ret.data[i] = bytes.data[i];
        }
        for ( ; i < 20; i++) {
            ret.data[i] = 0;
        }
        return ret;
    }
    //static_assert("Invalid Transformation!\n");
}

uint256_t Transform::bytesToUint256(Bytes bytes) {
    uint256_t ret = 0;
    for (int i = 0; i < bytes.data.size(); i++) {
        ret = ret * 256 + bytes.data[i];
    }
    return ret;
}

uint64_t Transform::bytesToUint64(Bytes bytes) {
    uint64_t ret = 0;
    for (int i = 0; i < bytes.data.size(); i++) {
        ret = ret * 256 + bytes.data[i];
    }
    return ret;
}

unsigned int Transform::bytesToUint(Bytes bytes) {
    unsigned int ret = 0;
    for (int i = 0; i < bytes.data.size(); i++) {
        ret = ret * 256 + bytes.data[i];
    }
    return ret;
}

Bytes Transform::hashToBytes(ethash_h256_t hash) {
    Bytes ret;
    for (int i = 0; i < 32; i++) {
        ret.data.push_back(hash.b[i]);
    }
    return ret;
}

std::string Transform::hashToHexString(ethash_h256_t hash) {
    return bytesToHexString(hashToBytes(hash));
}

Bytes Transform::addrToBytes(Address addr) {
    Bytes ret;
    for (int i = 0; i < 20; i++) {
        ret.data.push_back(addr.data[i]);
    }
    return ret;
}

uint256_t Transform::intStringToUint256(std::string st) {
    uint256_t ret = 0;
    for (int i = 0; i < st.length(); i++) {
        ret *= 10;
        ret += st[i] - '0';
    }
    return ret;
}

ethash_h256_t Transform::uint256ToHash(uint256_t x) {
    ethash_h256_t ret;
    int i;
    for (i = 0; x > 0; i++) {
        ret.b[32 - i - 1] = x % 256;
        x /= 256;
    }
    for (; i < 32; i++) {
        ret.b[32 - i - 1] = 0;
    }
    return ret;
}

Bytes Transform::uint256ToBytes(uint256_t x) {
    Bytes ret;
    while (x > 0) {
        ret.data.push_back(uint8_t(x % 256));
        x /= 256;
    }
    std::reverse(ret.data.begin(), ret.data.end());
    return ret;
}

Bytes Transform::intToBytes(int x) {
    Bytes ret;
    if (x != 0) {
        ret = intToBytes(x / 256) + Bytes(x % 256);
    }
    return ret;
}

Bytes Transform::uint64ToBytes(uint64_t x) {
    Bytes ret;
    if (x != 0) {
        ret = uint64ToBytes(x / 256) + Bytes(x % 256);
    }
    return ret;
}