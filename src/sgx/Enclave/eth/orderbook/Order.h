

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
        if (primeCoinType == rhs.primeCoinType) {
            return address < rhs.address;
        }
        return primeCoinType < rhs.primeCoinType;
    }

    bool operator== (const CoinType & rhs) const{
        return primeCoinType == rhs.primeCoinType && address == rhs.address;
    }

    bool operator!= (const CoinType & rhs) const{
        return primeCoinType != rhs.primeCoinType || address != rhs.address;
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
    uint256_t orderCounter = 0;

    uint256_t orderNumber;//0-based &
    User user;
    CoinPair coinPair;
    OrderType orderType;
    VolumeType volume;
    PriceType price;

    Order(User user, CoinPair coinPair, OrderType orderType, VolumeType volume, PriceType price):
        user(user), coinPair(coinPair), orderType(orderType), volume(volume), price(price) {
        orderNumber = orderCounter++;
        //orderNumber recycle
    }

    bool operator< (const Order & rhs) const {
        return price < rhs.price;
    }
};

class UserAccount{//in accountSys
public:
    CoinType coinType;
    Address address;

    UserAccount(CoinType coinType, Address address):
            coinType(coinType), address(address) {}

    bool operator< (const UserAccount & rhs) const {
        if (coinType != rhs.coinType) {
            return coinType < rhs.coinType;
        }
        return address < rhs.address;
    }
};

class Withdraw{
public:
    UserAccount userAccount;
    VolumeType volume;

    Withdraw(UserAccount userAccount, VolumeType volume):
            userAccount(userAccount), volume(volume) {}
};