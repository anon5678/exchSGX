
#ifndef EXCHSGX_COPY_ORDERBOOK_H
#define EXCHSGX_COPY_ORDERBOOK_H

#endif //EXCHSGX_COPY_ORDERBOOK_H

#include <set>

#include "../common/RLP.h"

class OrderBook {
public:
    /*
     * coinPair (coinA, coinB)
     * SELL : coinA -> coinB
     * BUY : coinB -> coinA
     */
    std::multiset<Order> sellBook, buyBook;

    PriceType buyBookGetMaxPrice();
    Order buyBookPopMaxPriceOrder();

    PriceType sellBookGetMinPrice();
    Order sellBookPopMinPriceOrder();
};