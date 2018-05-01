//
// Created by lilione on 2018/3/30.
//

#include "ReceiptProof.h"

#include "../../log.h"

#include "RLP.h"
#include "Transform.h"

Receipt ReceiptProof::receiptProofVerify(ethash_h256_t receiptRootHash) {
    /*ethash_h256_t receiptRootHash = state::queue.getReceiptRoot(blockNumber);
    if (!receiptRootHash) {
        LL_CRITICAL("Invalid blockNumber");
        return NULL;
    }*/
    //ethash_h256_t receiptRootHash = Transform::bytesToHash(keccak(RLP::encodeList(receiptProof.path[0].content)));

    auto ret = Proof::verifyProof(Transform::bytesToHexString(key), path, receiptRootHash);

    if (!ret.second) {
        LL_CRITICAL("receiptProof Failed!");
        //return empty
    }
    else {
        LL_NOTICE("receiptProof Success!");
        RLP::decodeReceipt(ret.first);
        //return Receipt
    }
}
