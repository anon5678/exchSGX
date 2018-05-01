//
// Created by lilione on 2017/11/22.
//

#ifndef MERKLE_PARTRICIA_TREE_RECEIPTPROOF_H
#define MERKLE_PARTRICIA_TREE_RECEIPTPROOF_H

#include "Proof.h"
#include "Receipt.h"
#include "uint256_t.h"

class ReceiptProof : public Proof {
public:
    ReceiptProof(Bytes key, std::vector<Node> path):
            Proof(key, path) {}

    Receipt receiptProofVerify(ethash_h256_t);
};


#endif //MERKLE_PARTRICIA_TREE_RECEIPTPROOF_H
