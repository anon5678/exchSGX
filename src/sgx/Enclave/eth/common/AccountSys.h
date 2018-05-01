//
// Created by lilione on 2018/3/29.
//

#include <map>

#include "uint256_t.h"
#include "Address.h"

class AccountSys {
public:
    //(userAddr, tokenAddr)
    std::map<std::pair<Address, Address>, uint256_t> deposit;
    std::map<std::pair<Address, Address>, int> sign;//either 1 or -1, default is 1
    std::map<std::pair<Address, Address>, uint256_t> delta;
    std::map<std::pair<Address, Address>, uint256_t> expire;
};