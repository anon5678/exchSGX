

#ifndef EXCHSGX_COPY_ORDER_H
#define EXCHSGX_COPY_ORDER_H

#endif //EXCHSGX_COPY_ORDER_H

#include <map>

#include "FixedDecimal.h"
#include "../common/Address.h"
#include "../common/uint256_t.h"

enum PrimeCoinType {BTC, ETH, LTC};
class CoinType {
public:
    /*
     * ETH : 0       Ether
     *       other   token
     *
     * BTC & LTC : address is empty
    */

    PrimeCoinType primeCoinType;
    Address address;

    CoinType(PrimeCoinType primeCoinType): primeCoinType(primeCoinType) {}

    CoinType(PrimeCoinType primeCoinType, Address address): primeCoinType(primeCoinType), address(address) {}

    bool operator< (const CoinType & rhs) const {
        return address < rhs.address;
    }
};
/*
 * coinPair (coinA, coinB)
 * SELL : coinA -> coinB
 * BUY : coinB -> coinA
 */
typedef std::pair<CoinType , CoinType> CoinPair;

typedef uint256_t VolumeType;
typedef FixedDecimal<VolumeType, 5> PriceType;

enum OrderType {SELL, BUY};

class User {
public:
    std::map<PrimeCoinType, Address> addr;
};

class Order {
public:
    User user;
    CoinPair coinPair;
    OrderType orderType;
    VolumeType volume;
    PriceType price;

    Order(User user, CoinPair coinPair, OrderType orderType, VolumeType volume, PriceType price):
        user(user), coinPair(coinPair), orderType(orderType), volume(volume), price(price) {}

    bool operator< (const Order & rhs) const {
        return price < rhs.price;
    }
};