

#include "OrderBook.h"

PriceType OrderBook::buyBookGetMaxPrice() {
    return (*buyBook.rbegin()).price;
}

Order OrderBook::buyBookPopMaxPriceOrder() {
    Order order = *(--buyBook.end());
    buyBook.erase(--buyBook.end());
    return order;
}

PriceType OrderBook::sellBookGetMinPrice() {
    return (*sellBook.begin()).price;
}

Order OrderBook::sellBookPopMinPriceOrder() {
    Order order = *sellBook.begin();
    sellBook.erase(sellBook.begin());
    return order;
}