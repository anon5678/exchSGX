//
// Created by lilione on 2018/3/29.
//

#include <map>

#include "uint256_t.h"
#include "Address.h"
#include "RLP.h"

typedef uint256_t TimeStamp;

class AccountSys {
public:
    //(userAddr, coinType)
    std::map<UserAccount, VolumeType> deposit;
    std::map<UserAccount, int> sign;//either 1 or -1, default is 1
    std::map<UserAccount, VolumeType> delta;
    std::map<UserAccount, TimeStamp> expire;

    void trade(UserAccount, UserAccount, VolumeType);

    void minus(UserAccount, VolumeType);
    void add(UserAccount, VolumeType);

    bool checkBalance(UserAccount, VolumeType);
};