//
// Created by lilione on 2017/10/24.
//

#ifndef MERKLE_PARTRICIA_TREE_ACCOUNTPROOF_H
#define MERKLE_PARTRICIA_TREE_ACCOUNTPROOF_H

#include "Proof.h"

class AccountProof : public Proof {
public:
    AccountProof(Bytes key, std::vector<Node> path):
            Proof(key, path) {}
};


#endif //MERKLE_PARTRICIA_TREE_ACCOUNTPROOF_H
