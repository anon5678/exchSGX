
#include "Server.h"

bool Server::checkBalance(Order order) {
    CoinType coinType = order.orderType == SELL ? order.coinPair.first : order.coinPair.second;
    Address userAddress = order.orderType == SELL ?
                          order.user.addr[order.coinPair.first.primeCoinType] :
                          order.user.addr[order.coinPair.second.primeCoinType];
    UserAccount userAccount = UserAccount(coinType, userAddress);
    return accountSys.expire[userAccount] - SAFE_TIME >= queue.getNewestBlockNumber() &&
           accountSys.checkBalance(userAccount, order.volume);
}

void Server::receiveOrder(const char* _st) {

    std::string st(_st);
    Bytes bytes = Transform::hexStringToBytes(st);

    Order order = RLP::decodeOrder(bytes);

    CoinPair coinPair = order.coinPair;
    OrderBook &orderBook = orderBooks[coinPair];
    //check lock and lock corresponding orderbook

    VolumeType volume = order.volume;
    PriceType price = order.price;

    //SELL coinA -> coinB
    if (order.orderType == SELL) {
        if (!checkBalance(order)) {
            LL_NOTICE("Invalid Sell Order!");
            return;
        }
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
                accountSys.trade(UserAccount(first, seller.addr[first.primeCoinType]), UserAccount(first, buyer.addr[first.primeCoinType]), txVolume);
                accountSys.trade(UserAccount(second, buyer.addr[second.primeCoinType]), UserAccount(second, seller.addr[second.primeCoinType]), (buyPrice * txVolume).round());

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
        if (!checkBalance(order)) {
            return;
        }
        while (!orderBook.sellBook.empty()) {
            if (volume <= 0) {
                LL_NOTICE("Invalid Buy Order!");
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
                accountSys.trade(UserAccount(first, seller.addr[first.primeCoinType]), UserAccount(first, buyer.addr[first.primeCoinType]), txVolume);
                accountSys.trade(UserAccount(second, buyer.addr[second.primeCoinType]), UserAccount(second, seller.addr[second.primeCoinType]), (sellPrice * txVolume).round());

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

void Server::receiveWithdraw(const char * _st) {
    std::string st(_st);
    Bytes bytes = Transform::hexStringToBytes(st);

    Withdraw withdraw = RLP::decodeWithdraw(bytes);

    UserAccount userAccount = withdraw.userAccount;
    VolumeType volume = withdraw.volume;

    if (queue.getNewestBlockNumber() <= accountSys.expire[userAccount]) {
        LL_CRITICAL("Too Early to Withdraw!");
        return;
    }

    if (accountSys.checkBalance(userAccount, volume)) {
        accountSys.minus(userAccount, volume);
    }
    else {
        LL_CRITICAL("Not Enough Balance!");
        return;
    }
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

    UserAccount useraccount = UserAccount(CoinType(ETH, tokenAddr), userAddr);

    if (expiration <= accountSys.expire[useraccount]) {
        LL_CRITICAL("Non-increasing Expiration!");
        return;
    }

    if (!accountSys.sign.count(useraccount)) {
        accountSys.sign[useraccount] = 1;
        accountSys.delta[useraccount] = 0;
    }
    accountSys.deposit[useraccount] = balance;
    accountSys.expire[useraccount] = expiration;

    LL_NOTICE("Deposit Update Successfully!");
}

void Server::receiveHeaders(const char * _st) {
    std::string st(_st);
    Bytes bytes = Transform::hexStringToBytes(st);

    std::vector<Header> headers = RLP::decodeHeaders(bytes);
    for (int i = 0; i < headers.size(); i++) {
        queue.addNewHeader(headers[i]);
    }
}