//
// Created by lilione on 2017/9/20.
//

#include <cstdio>
#include <iostream>
#include <cmath>
//#include <sys/param.h>
#include <sstream>

#include "Header.h"
#include "Utils.h"
#include "../libethash/internal.h"
#include "Transform.h"
#include "RLP.h"
#include "Keccak.h"

#include "../../log.h"

ethash_h256_t Header::getDivide(uint256_t diff) {
    uint256_t TwoTo255 = Utils::power(2, 255);
    uint256_t _ret = TwoTo255 / diff * 2 + TwoTo255 % diff * 2 / diff;
    return Transform::uint256ToHash(_ret);
}

bool PoWCheck(Header header) {
    ethash_light_t light = ethash_light_new(header.number);
    if (!light) return false;
    ethash_return_value_t ret = ethash_light_compute(
            light,
            header.minerHash,
            header.nonce
    );
    if (!Utils::equal(ret.mix_hash, header.mixHash)) return false;
    if (!ethash_check_difficulty(&ret.result, &header.diffAfterDivide)) return false;
    ethash_light_delete(light);
    return true;
}

bool difficultyCheck(Header header, Header parentHeader) {
    const uint256_t D_0 = 131072, N_H = 1150000;
    uint256_t x = parentHeader.difficulty / 2048;
    uint256_t D_H = parentHeader.difficulty;
    if (header.number >= N_H) {
        uint256_t tmp = (header.timestamp - parentHeader.timestamp) / 10;
        if (tmp == 0) {
            D_H += x;
        }
        else {
            D_H -= x * Utils::min(tmp - 1, 99);
        }
    }
    else if (header.timestamp < parentHeader.timestamp + 13) {
        D_H += x;
    }
    else {
        D_H -= x;
    }
    uint256_t sigma = Utils::power(2, header.number / 100000 - 2);
    D_H += sigma;
    D_H = Utils::max(D_0, D_H);
    return header.difficulty == D_H;
}

bool gasCheck(Header header, Header parentHeader) {
    if (header.gasUsed > header.gasLimit) return false;
    uint256_t tmp = parentHeader.gasLimit / 1024;
    if (header.gasLimit > parentHeader.gasLimit + tmp) return false;
    if (header.gasLimit < parentHeader.gasLimit - tmp) return false;
    return header.gasLimit >= 125000;
}

bool timestampCheck(Header header, Header parentHeader) {
    return header.timestamp > parentHeader.timestamp;
}

bool blockNumberCheck(Header header, Header parentHeader) {
    return header.number == parentHeader.number + 1;
}

bool extraDataCheck(Header header) {
    return header.extraData.data.size() <= 32;
}

bool hashCheck(Header header, Header parentHeader) {
    return Utils::equal(header.parentHash, parentHeader.blockHash);
}

bool Header::check(Header header, Header parentHeader) {
    if (!difficultyCheck(header, parentHeader)) {
        LL_CRITICAL("difficultyCheck failed!");
        return false;
    }
    if (!gasCheck(header, parentHeader)) {
        LL_CRITICAL("gasCheck failed!");
        return false;
    }
    if (!timestampCheck(header, parentHeader)) {
        LL_CRITICAL("timestampCheck failed!");
        return false;
    }
    if (!blockNumberCheck(header, parentHeader)) {
        LL_CRITICAL("blockNumberCheck failed!");
        return false;
    }
    if (!extraDataCheck(header)) {
        LL_CRITICAL("extraDataCheck failed!");
        return false;
    }
    if (!hashCheck(header, parentHeader)) {
        LL_CRITICAL("hashCheck failed!");
        return false;
    }
    if (!PoWCheck(header)) {
        LL_CRITICAL("PoWCheck failed!");
        return false;
    }
    return true;
}

ethash_h256_t Header::calcMinerHash() {
    std::vector<Bytes> list;
    list.push_back(RLP::encodeString(Transform::hashToBytes(parentHash)));
    list.push_back(RLP::encodeString(Transform::hashToBytes(uncleHash)));
    list.push_back(RLP::encodeString(Transform::addrToBytes(coinBase)));
    list.push_back(RLP::encodeString(Transform::hashToBytes(stateRoot)));
    list.push_back(RLP::encodeString(Transform::hashToBytes(txRoot)));
    list.push_back(RLP::encodeString(Transform::hashToBytes(receiptRoot)));
    list.push_back(RLP::encodeString(logsBloom));
    list.push_back(RLP::encodeString(Transform::uint256ToBytes(difficulty)));
    list.push_back(RLP::encodeString(Transform::uint256ToBytes(number)));
    list.push_back(RLP::encodeString(Transform::uint256ToBytes(gasLimit)));
    list.push_back(RLP::encodeString(Transform::uint256ToBytes(gasUsed)));
    list.push_back(RLP::encodeString(Transform::uint256ToBytes(timestamp)));
    list.push_back(RLP::encodeString(extraData));
    Bytes rlp = RLP::encodeList(list);
    Keccak keccak;
    Bytes hash = keccak(rlp);
    return Transform::bytesToHash(hash);
}

ethash_h256_t Header::calcBlockHash() {
    std::vector<Bytes> list;
    list.push_back(RLP::encodeString(Transform::hashToBytes(parentHash)));
    list.push_back(RLP::encodeString(Transform::hashToBytes(uncleHash)));
    list.push_back(RLP::encodeString(Transform::addrToBytes(coinBase)));
    list.push_back(RLP::encodeString(Transform::hashToBytes(stateRoot)));
    list.push_back(RLP::encodeString(Transform::hashToBytes(txRoot)));
    list.push_back(RLP::encodeString(Transform::hashToBytes(receiptRoot)));
    list.push_back(RLP::encodeString(logsBloom));
    list.push_back(RLP::encodeString(Transform::uint256ToBytes(difficulty)));
    list.push_back(RLP::encodeString(Transform::uint256ToBytes(number)));
    list.push_back(RLP::encodeString(Transform::uint256ToBytes(gasLimit)));
    list.push_back(RLP::encodeString(Transform::uint256ToBytes(gasUsed)));
    list.push_back(RLP::encodeString(Transform::uint256ToBytes(timestamp)));
    list.push_back(RLP::encodeString(extraData));
    list.push_back(RLP::encodeString(Transform::hashToBytes(mixHash)));
    list.push_back(RLP::encodeString(Transform::uint64ToBytes(nonce)));
    Bytes rlp = RLP::encodeList(list);
    Keccak keccak;
    Bytes hash = keccak(rlp);
    return Transform::bytesToHash(hash);
}

/*void Header::output(Header header) {
    printf("parentHash\n");
    Utils::outputHex(header.parentHash);
    printf("uncleHash\n");
    Utils::outputHex(header.uncleHash);
    printf("coinBase\n");
    Address::outputHex(header.coinBase);
    printf("stateRoot\n");
    Utils::outputHex(header.stateRoot);
    printf("txRoort\n");
    Utils::outputHex(header.txRoot);
    printf("receiptRoot\n");
    Utils::outputHex(header.receiptRoot);
    printf("logsBloom\n");
    Bytes::outputHex(header.logsBloom);
    printf("difficulty\n");
    std::cout<<header.difficulty<<std::endl;
    printf("number\n");
    std::cout<<header.number<<std::endl;
    std::cout<<header.gasLimit<<std::endl;
    std::cout<<header.gasUsed<<std::endl;
    std::cout<<header.timestamp<<std::endl;
    Bytes::outputHex(header.extraData);
    printf("mixHash\n");
    Utils::outputHex(header.mixHash);
    printf("nonce\n");
    std::cout<<header.nonce<<std::endl;

    printf("minerHash\n");
    Utils::outputHex(header.minerHash);
    Utils::outputHex(header.diffAfterDivide);
    printf("blockHash\n");
    Utils::outputHex(header.blockHash);
}*/
