
#include "Server.h"

bool Server::checkBalance(Address userAddr, Address tokenAddr, uint256_t volume) {
    std::pair<Address, Address> pair = std::make_pair(userAddr, tokenAddr);
    return accountSys.deposit[pair] + accountSys.sign[pair] * accountSys.delta[pair] >= 0 && queue.getNewestBlockNumber() <= accountSys.expire[pair] - SAFE_TIME;
}

bool Server::checkBalance(Order order) {
    if (order.orderType == SELL) {
        if (order.coinPair.first.primeCoinType == ETH) {
            if (!checkBalance(order.user.addr[ETH], order.coinPair.first.address, order.volume)) {
                return false;
            }
        }
    }
    else {
        if (order.coinPair.second.primeCoinType == ETH) {
            if (!checkBalance(order.user.addr[ETH], order.coinPair.second.address, order.volume)) {
                return false;
            }
        }
    }
    //TBD : BTC and LTC
}

void Server::receiveOrder(Order order) {
    CoinPair coinPair = order.coinPair;
    OrderBook &orderBook = orderBooks[coinPair];
    //check lock and lock corresponding orderbook

    VolumeType volume = order.volume;
    PriceType price = order.price;

    //SELL coinA -> coinB
    if (order.orderType == SELL) {
        if (!checkBalance(order)) return;
        while (!orderBook.buyBook.empty()) {
            if (volume <= 0) {
                break;
            }
            if (orderBook.buyBookGetMaxPrice() >= price) {
                Order buyOrder = orderBook.buyBookPopMaxPriceOrder();
                if (!checkBalance(buyOrder)) continue;

                PriceType buyPrice = buyOrder.price;
                VolumeType buyVolume = buyOrder.volume;
                VolumeType txVolume = std::min(buyVolume, volume);

                User seller = order.user, buyer = buyOrder.user;

                CoinType first = coinPair.first, second = coinPair.second;
                pools[first].add(Tx(seller.addr[first.primeCoinType], buyer.addr[first.primeCoinType], txVolume));
                pools[second].add(Tx(buyer.addr[second.primeCoinType], seller.addr[second.primeCoinType], (buyPrice * txVolume).round()));

                if (volume < buyVolume) {
                    buyOrder.volume -= txVolume;
                    orderBook.buyBook.insert(buyOrder);
                }
                volume -= txVolume;
            } else {
                break;
            }
        }
        if (volume > 0) {
            order.volume = volume;
            orderBook.sellBook.insert(order);
        }
    }
    //BUY coinB -> coinA
    else {
        if (!checkBalance(order)) return;
        while (!orderBook.sellBook.empty()) {
            if (volume <= 0) {
                break;
            }
            if (orderBook.sellBookGetMinPrice() <= price) {
                Order sellOrder = orderBook.sellBookPopMinPriceOrder();
                if (!checkBalance(sellOrder)) continue;

                PriceType sellPrice = sellOrder.price;
                VolumeType sellVolume = sellOrder.volume;
                VolumeType txVolume = std::min(sellVolume, volume);

                User seller = sellOrder.user, buyer = order.user;

                CoinType first = coinPair.first, second = coinPair.second;
                pools[first].add(Tx(seller.addr[first.primeCoinType], buyer.addr[first.primeCoinType], txVolume));
                pools[second].add(Tx(buyer.addr[second.primeCoinType], seller.addr[second.primeCoinType], (sellPrice * txVolume).round()));
                if (volume < sellVolume) {
                    sellOrder.volume -= txVolume;
                    orderBook.sellBook.insert(sellOrder);
                }
                volume -= txVolume;
            }
            else {
                break;
            }
        }
        if (volume > 0) {
            order.volume = volume;
            orderBook.buyBook.insert(order);
        }
    }
    //unlock corresponding orderbook
}

uint256_t Server::ValueProofVerify(ValueProof valueProof, ethash_h256_t accountRootHash) {
    AccountProof accountProof = valueProof.accountProof;
    ContentProof contentProof = valueProof.contentProof;

    auto ret = Proof::verifyProof(Transform::bytesToHexString(accountProof.key), accountProof.path, accountRootHash);

    if (!ret.second) {
        LL_CRITICAL("accountProof Failed!");
        return 0;
    }
    LL_NOTICE("accountProof Success!");

    Account account = RLP::decodeAccount(ret.first);
    ethash_h256_t contentRootHash = account.rootHash;

    ret = Proof::verifyProof(Transform::bytesToHexString(contentProof.key), contentProof.path, contentRootHash);

    if (!ret.second) {
        LL_CRITICAL("contentProof Failed!");
        return 0;
    }
    LL_NOTICE("contentProof Success!");

    Bytes _content = RLP::remove_length(ret.first);
    uint256_t content = Transform::bytesToUint256(_content);

    LL_NOTICE("Value is %d.\n", uint64_t(content));
    return content;
}

void Server::proofsVerify(const char* _st) {
    //TBD : check lock

    std::string st(_st);
    Bytes bytes = Transform::hexStringToBytes(st);

    std::pair<uint256_t, std::pair<ValueProof, ValueProof> > depositProof = RLP::decodeDepositProof(bytes);
    uint256_t blockNumber = depositProof.first;
    ValueProof balanceProof = depositProof.second.first;
    ValueProof expireProof = depositProof.second.second;

    //TBD : check pos

    ethash_h256_t accountRootHash = queue.getStateRoot(blockNumber);
    if (Utils::check_ethash_h256_(accountRootHash)) {
        LL_CRITICAL("Invalid Block Number!");
        return;
    }
    //ethash_h256_t accountRootHash = Transform::bytesToHash(keccak(RLP::encodeList(accoutProof.path[0].content)));

    uint256_t balance = ValueProofVerify(balanceProof, accountRootHash);
    if (!balance) {
        LL_CRITICAL("Balance Proof Failed!");
        return;
    }

    uint256_t expiration = ValueProofVerify(expireProof, accountRootHash);
    if (!expiration) {
        LL_CRITICAL("Expiration Proof Failed!");
        return;
    }

    Address userAddr = balanceProof.contentProof.userAddr;
    Address tokenAddr = balanceProof.contentProof.tokenAddr;

    if (expireProof.contentProof.userAddr != userAddr || expireProof.contentProof.tokenAddr != tokenAddr) {
        LL_CRITICAL("Unequal userAddr or tokenAddr!");
        return;
    }

    std::pair<Address, Address> pair = std::make_pair(userAddr, tokenAddr);

    if (expiration <= accountSys.expire[pair]) {
        LL_CRITICAL("Non-increasing Expiration!");
        return;
    }

    if (!accountSys.sign.count(pair)) {
        accountSys.sign[pair] = 1;
        accountSys.delta[pair] = 0;
    }
    accountSys.deposit[pair] = balance;
    accountSys.expire[pair] = expiration;

    LL_NOTICE("Deposit Update Successfully!");
}