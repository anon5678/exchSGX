//
// Created by lilione on 2017/8/23.
//

#ifndef MERKLE_PARTRICIA_TREE_RLP_H
#define MERKLE_PARTRICIA_TREE_RLP_H

#include <cstdint>
#include <vector>

#include "Bytes.h"
#include "Account.h"
#include "Header.h"
#include "ReceiptProof.h"
#include "ValueProof.h"
#include "uint256_t.h"
#include "../orderbook/Order.h"

class RLP {
public:
    static Bytes encodeString(Bytes);
    static Bytes encodeList(std::vector<Bytes>);
    static Bytes encodeLength(int, int);

    static ValueProof decodeValueProof(Bytes);
    static Account decodeAccount(Bytes);
    static Header decodeHeader(Bytes);
    static std::pair<uint256_t, ReceiptProof> decodeReceiptProof(Bytes);
    static bool decodeReceipt(Bytes);
    static std::pair<uint256_t, std::pair<ValueProof, ValueProof> > decodeDepositProof(Bytes);

    static Order decodeOrder(Bytes);
    static User decodeUser(Bytes);
    static CoinPair decodeCoinPair(Bytes);
    static CoinType decodeCoinType(Bytes);
    static OrderType decodeOrderType(Bytes);

    static std::vector<Bytes> decodeList(Bytes);
    static Bytes remove_length(Bytes);
    static int decodeLength(Bytes, int&);
};

#endif //MERKLE_PARTRICIA_TREE_RLP_H
