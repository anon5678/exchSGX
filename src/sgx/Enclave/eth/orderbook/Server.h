

#ifndef EXCHSGX_COPY_SERVER_H
#define EXCHSGX_COPY_SERVER_H

#endif //EXCHSGX_COPY_SERVER_H

#include "../../log.h"

#include "OrderBook.h"
#include "TxPool.h"
#include "../common/AccountSys.h"
#include "../common/Queue.h"

#include "../common/uint256_t.h"
#include "../common/Transform.h"
#include "../libethash/ethash.h"
#include "../common/Utils.h"

class Server {
public:
    const uint256_t SAFE_TIME = 30;

    std::map<CoinPair, OrderBook> orderBooks;
    std::map<CoinType, TxPool> pools;
    AccountSys accountSys;
    Queue queue;

    bool checkBalance(Address, Address, uint256_t);
    bool checkBalance(Order);
    void receiveOrder(Order);//input : string

    uint256_t ValueProofVerify(ValueProof, ethash_h256_t);
    void proofsVerify(const char*);
};
