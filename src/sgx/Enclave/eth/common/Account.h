//
// Created by lilione on 2017/9/13.
//

#ifndef MERKLE_PARTRICIA_TREE_ACCOUNT_H
#define MERKLE_PARTRICIA_TREE_ACCOUNT_H

#include "Bytes.h"
#include "uint256_t.h"
#include "../libethash/ethash.h"

class Account {
public:
    uint64_t nonce;
    uint256_t balance;
    ethash_h256_t rootHash;
    ethash_h256_t codeHash;

    Account(uint64_t nonce, uint256_t balance, ethash_h256_t rootHash, ethash_h256_t codeHash):
            nonce(nonce), balance(balance), rootHash(rootHash), codeHash(codeHash) {}
};


#endif //MERKLE_PARTRICIA_TREE_ACCOUNT_H
