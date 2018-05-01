//
// Created by lilione on 2017/8/23.
//

#include <cstdint>
#include <vector>
#include <string>
#include <iostream>

#include "RLP.h"
#include "Keccak.h"
#include "Transform.h"

const int offset_string = 128;
const int offset_list = 192;

Bytes RLP::encodeString(Bytes input) {
    if (input.data.size() == 1 && input.data[0] < 128) {
        return input;
    }
    return encodeLength(input.data.size(), 128) + input;
}

Bytes RLP::encodeList(std::vector<Bytes> list) {
    Bytes ret;
    for (int i = 0; i < list.size(); i++) {
        ret = ret + list[i];
    }
    return encodeLength(ret.data.size(), 192) + ret;
}

Bytes RLP::encodeLength(int L, int offset) {
    //len should be less than 256**8
    if (L < 56) {
        return Bytes(L + offset);
    }
    Bytes BL = Transform::intToBytes(L);
    return Bytes(BL.data.size() + offset + 55) + BL;
}

ValueProof RLP::decodeValueProof(Bytes input) {
    Keccak keccak;
    RLP rlp;

    std::vector<Bytes> elements = decodeList(input);
    std::vector<Bytes> path_list = decodeList(elements[0]);
    std::vector<Node> path;
    for (int i = 0; i < path_list.size(); i++) {
        path.push_back(Node(decodeList(path_list[i])));
    }
    Bytes key = keccak(remove_length(elements[1]));
    AccountProof accoutProof = AccountProof(key, path);

    path_list = decodeList(elements[2]);
    path.clear();
    for (int i = 0; i < path_list.size(); i++) {
        path.push_back(Node(decodeList(path_list[i])));
    }

    Bytes _userAddr = remove_length(elements[3]);
    Bytes _tokenAddr = remove_length(elements[4]);
    Bytes _pos = remove_length(elements[5]);
    key = keccak(keccak(_userAddr + keccak(_tokenAddr + _pos)));

    Address userAddr = Transform::bytesToAddr(_userAddr);
    Address tokenAddr = Transform::bytesToAddr(_tokenAddr);
    unsigned int pos = Transform::bytesToUint(_pos);

    ContentProof contentProof = ContentProof(key, path, pos, tokenAddr, userAddr);

    return ValueProof(accoutProof, contentProof);
};

Account RLP::decodeAccount(Bytes input) {
    std::vector<Bytes> elements = decodeList(input);
    Bytes _nonce = remove_length(elements[0]);
    unsigned int nonce = 0;
    for (int i = 0; i < _nonce.data.size(); i++) {
        nonce = nonce * 256 + _nonce.data[i];
    }
    Bytes _balance = remove_length(elements[1]);
    uint256_t balance = 0;
    for (int i = 0; i < _balance.data.size(); i++) {
        balance = balance * 256 + _balance.data[i];
    }
    ethash_h256_t rootHash = Transform::bytesToHash(remove_length(elements[2]));
    ethash_h256_t codeHash = Transform::bytesToHash(remove_length(elements[3]));
    return Account(nonce, balance, rootHash, codeHash);
}

Header RLP::decodeHeader(Bytes input) {
    std::vector<Bytes> elements = decodeList(input);
    ethash_h256_t parentHash = Transform::bytesToHash(remove_length(elements[0]));
    ethash_h256_t uncleHash = Transform::bytesToHash(remove_length(elements[1]));
    Address coinBase = Transform::bytesToAddr(remove_length(elements[2]));
    ethash_h256_t stateRoot = Transform::bytesToHash(remove_length(elements[3]));
    ethash_h256_t txRoot = Transform::bytesToHash(remove_length(elements[4]));
    ethash_h256_t receiptRoot = Transform::bytesToHash(remove_length(elements[5]));
    Bytes logsBloom = remove_length(elements[6]);
    uint256_t difficulty = Transform::bytesToUint256(remove_length(elements[7]));
    uint256_t number = Transform::bytesToUint256(remove_length(elements[8]));
    uint256_t gasLimit = Transform::bytesToUint256(remove_length(elements[9]));
    uint256_t gasUsed = Transform::bytesToUint256(remove_length(elements[10]));
    uint256_t timestamp = Transform::bytesToUint256(remove_length(elements[11]));
    Bytes extraData = remove_length(elements[12]);
    ethash_h256_t mixHash = Transform::bytesToHash(remove_length(elements[13]));
    uint64_t nonce = Transform::bytesToUint64(remove_length(elements[14]));

    return Header(parentHash, uncleHash,
                  coinBase,
                  stateRoot, txRoot, receiptRoot,
                  logsBloom,
                  difficulty, number, gasLimit, gasUsed, timestamp,
                  extraData,
                  mixHash,
                  nonce);
}

std::pair<uint256_t, ReceiptProof> RLP::decodeReceiptProof(Bytes input) {
    std::vector<Bytes> elements = decodeList(input);
    std::vector<Bytes> path_list = decodeList(elements[0]);
    std::vector<Node> path;
    for (int i = 0; i < path_list.size(); i++) {
        path.push_back(Node(decodeList(path_list[i])));
    }
    Bytes key = remove_length(elements[1]);
    uint256_t blockNumber = Transform::bytesToUint64(remove_length(elements[2]));
    return std::make_pair(blockNumber, ReceiptProof(key, path));
}

bool RLP::decodeReceipt(Bytes input) {
    std::vector<Bytes> elements = decodeList(input);
    std::vector<Bytes> logs = decodeList(elements[3]);
    for (int i = 0; i < logs.size(); i++) {
        std::vector<Bytes> log = decodeList(logs[i]);
        //if (log.size()) return true;
        //else return false;
        Bytes address = remove_length(log[0]);
        std::vector<Bytes> topics = decodeList(log[1]);
        for (int j = 0; j < topics.size(); j++) {
            topics[j] = remove_length(topics[j]);
        }
        Bytes _data = remove_length(log[2]);
        std::vector<Bytes> data;
        while (_data.data.size()) {
            data.push_back(_data.substr(0, 32));
            _data = _data.substr(32);
        }
    }
}

std::pair<uint256_t, std::pair<ValueProof, ValueProof> > RLP::decodeDepositProof(Bytes input) {
    std::vector<Bytes> elements = decodeList(input);

    Bytes _blockNumber = remove_length(elements[0]);
    uint256_t blockNumber = Transform::bytesToUint(_blockNumber);

    ValueProof balanceProof = decodeValueProof(elements[1]);

    ValueProof expireProof = decodeValueProof(elements[2]);

    return std::make_pair(blockNumber, std::make_pair(balanceProof, expireProof));
};

Order RLP::decodeOrder(Bytes input) {
    std::vector<Bytes> elememts = decodeList(input);

    //user
    User user = decodeUser(elememts[0]);

    //coinPair
    CoinPair coinPair = decodeCoinPair(elememts[1]);

    //orderType
    OrderType orderType = decodeOrderType(elememts[2]);

    //volume
    VolumeType volume = Transform::bytesToUint256(remove_length(elememts[3]));

    //prime
    PriceType price = PriceType(Transform::bytesToUint256(remove_length(elememts[4])));

    return Order(user, coinPair, orderType, volume, price);
}

User RLP::decodeUser(Bytes input) {
    User user;
    std::vector<Bytes> elements = decodeList(input);
    if (remove_length(elements[0]).data.size()) {
        user.addr[BTC] = Transform::bytesToAddr(remove_length(elements[0]));
    }
    if (remove_length(elements[1]).data.size()) {
        user.addr[ETH] = Transform::bytesToAddr(remove_length(elements[1]));
    }
    if (remove_length(elements[2]).data.size()) {
        user.addr[LTC] = Transform::bytesToAddr(remove_length(elements[2]));
    }
    return user;
}

CoinPair RLP::decodeCoinPair(Bytes input) {
    std::vector<Bytes> elements = decodeList(input);
    return std::make_pair(decodeCoinType(elements[0]), decodeCoinType(elements[1]));
}

CoinType RLP::decodeCoinType(Bytes input) {
    std::vector<Bytes> elements = decodeList(input);
    std::string _primeCoinType = Transform::bytesToString(remove_length(elements[0]));
    if (_primeCoinType == "ETH") {
        return CoinType(ETH, Transform::bytesToAddr(remove_length(elements[1])));
    }
    else if (_primeCoinType == "BTC") {
        return CoinType(BTC);
    }
    else if (_primeCoinType == "LTC") {
        return CoinType(LTC);
    }
}

OrderType RLP::decodeOrderType(Bytes input) {
    std::string _orderType = Transform::bytesToString(remove_length(input));
    if (_orderType == "BUY") {
        return BUY;
    }
    else {
        return SELL;
    }
}

std::vector<Bytes> RLP::decodeList(Bytes input) {
    int pos = 0, len = decodeLength(input, pos);
    int end = len + pos;
    std::vector<Bytes> ret;
    int pre = pos;
    while (pos < end) {
        int now = decodeLength(input, pos);
        ret.push_back(input.substr(pre, pos + now));
        pos += now;
        pre = pos;
    }
    return ret;
}

Bytes RLP::remove_length(Bytes input) {
    int pos = 0, len = decodeLength(input, pos);
    return input.substr(pos, pos + len);
}

int RLP::decodeLength(Bytes input, int& pos) {
    int len, offset;
    if (input.data[pos] < offset_list) {
        if (input.data[pos] < 128) {
            return 1;
        }
        offset = offset_string;
    }
    else {
        offset = offset_list;
    }
    if (input.data[pos] <= offset + 55) {
        len = input.data[pos++] - offset;
    }
    else {
        int now = input.data[pos++] - offset - 55;
        len = 0;
        for (int i = 0; i < now; i++) {
            len = len * 256 + input.data[pos++];
        }
    }
    return len;
}