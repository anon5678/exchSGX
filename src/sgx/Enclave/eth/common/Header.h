//
// Created by lilione on 2017/9/20.
//

#ifndef POW_HEADER_H
#define POW_HEADER_H

#include <string>

#include "uint256_t.h"
#include "Address.h"
#include "Bytes.h"

class Header {
public:
    ethash_h256_t parentHash, uncleHash;
    Address coinBase;
    ethash_h256_t stateRoot, txRoot, receiptRoot;
    Bytes logsBloom;
    uint256_t difficulty, number, gasLimit, gasUsed, timestamp;
    Bytes extraData;//no more than 32 bytes
    ethash_h256_t mixHash;
    uint64_t nonce;

    ethash_h256_t minerHash, diffAfterDivide, blockHash;

    Header() = default;

    Header(uint256_t number) :
            number(number) {}

    Header(ethash_h256_t parentHash,
           ethash_h256_t uncleHash,
           Address coinBase,
           ethash_h256_t stateRoot,
           ethash_h256_t txRoot,
           ethash_h256_t receiptRoot,
           Bytes logsBloom,
           uint256_t difficulty,
           uint256_t number,
           uint256_t gasLimit,
           uint256_t gasUsed,
           uint256_t timestamp,
           Bytes extraData,
           ethash_h256_t mixHash,
           uint64_t nonce) :
            parentHash(parentHash),
            uncleHash(uncleHash),
            coinBase(coinBase),
            stateRoot(stateRoot),
            txRoot(txRoot),
            receiptRoot(receiptRoot),
            logsBloom(logsBloom),
            difficulty(difficulty),
            number(number),
            gasLimit(gasLimit),
            gasUsed(gasUsed),
            timestamp(timestamp),
            extraData(extraData),
            mixHash(mixHash),
            nonce(nonce)
    {
        diffAfterDivide = getDivide(difficulty);
        minerHash = calcMinerHash();
        blockHash = calcBlockHash();
    }

    bool operator == (const Header &rhs) const {
        return number == rhs.number;
    }

    ethash_h256_t getDivide(uint256_t);
    ethash_h256_t calcMinerHash();
    ethash_h256_t calcBlockHash();

    static bool check(Header header, Header parentHeader);

    static void output(Header);

};
#endif //POW_HEADER_H
