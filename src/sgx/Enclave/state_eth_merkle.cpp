//
// Created by lilione on 2017/11/14.
//

#include "state.h"

#include "eth/common/Keccak.h"
#include "eth/common/Utils.h"
#include "eth/common/RLP.h"
#include "eth/common/Proof.h"
#include "eth/common/ReceiptProof.h"
#include "eth/common/Transform.h"

using namespace exch::enclave;

int eth_balance_proof_verify(const char *_st) {
    try {
        /*std::string st(_st);

        Keccak keccak;

        Bytes encoded = Transform::hexStringToBytes(st);

        auto proofs = RLP::decodeBalanceProof(encoded);

        AccountProof accoutProof = proofs.first;
        BalanceProof balanceProof = proofs.second;

        //ethash_h256_t accountRootHash = state::queue.getLast().stateRoot;
        ethash_h256_t accountRootHash = Transform::bytesToHash(keccak(RLP::encodeList(accoutProof.path[0].content)));

        auto ret = Proof::verifyProof(Transform::bytesToHexString(accoutProof.key), accoutProof.path, accountRootHash);

        if (!ret.second) {
            LL_CRITICAL("accountProof Failed!");
            return -1;
        }
        LL_NOTICE("accountProof Success!");

        Account account = RLP::decodeAccount(ret.first);
        ethash_h256_t balanceRootHash = account.rootHash;

        ret = Proof::verifyProof(Transform::bytesToHexString(balanceProof.key), balanceProof.path, balanceRootHash);

        if (!ret.second) {
            LL_CRITICAL("balanceProof Failed!");
            return -1;
        }
        LL_NOTICE("balanceProof Success!");

        Bytes _balance = RLP::remove_length(ret.first);
        uint256_t balance = Transform::bytesToUint256(_balance);

        Inf inf = Inf(balanceProof.pos, balanceProof.tokenAddr, balanceProof.userAddr, balance);
        LL_NOTICE("%d\n", uint64_t(balance));
        return 0;*/
    }
    catch (const std::exception &e) {
        LL_CRITICAL("exception in ecall: %s", e.what());
        return -1;
    }
}

int eth_receipt_proof_verify(const char *_st) {
    try {
        /*std::string st(_st);

        Keccak keccak;

        Bytes encoded = Transform::hexStringToBytes(st);

        ReceiptProof receiptProof = RLP::decodeReceiptProof(encoded);

        ethash_h256_t receiptRootHash = Transform::bytesToHash(keccak(RLP::encodeList(receiptProof.path[0].content)));

        //ethash_h256_t accountRootHash = queue.getLast().stateRoot;
        auto ret = Proof::verifyProof(Transform::bytesToHexString(receiptProof.key), receiptProof.path, receiptRootHash);

        if (!ret.second) {
            LL_CRITICAL("receiptProof Failed!");
            return -1;
        }
        else {
            LL_NOTICE("receiptProof Success!");
            RLP::decodeReceipt(ret.first);
            return 0;
        }*/
    }
    catch (const std::exception &e) {
        LL_CRITICAL("exception in ecall: %s", e.what());
        return -1;
    }
}