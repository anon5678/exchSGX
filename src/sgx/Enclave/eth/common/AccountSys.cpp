//
// Created by lilione on 8/30/18.
//

#include "AccountSys.h"

void AccountSys::trade(UserAccount from, UserAccount to, VolumeType volume) {
    minus(from, volume);
    add(to, volume);
}

void AccountSys::minus(UserAccount userAccount, VolumeType volume) {
    //check lock & lock
    if (sign[userAccount] == 1) {
        if (delta[userAccount] < volume) {
            sign[userAccount] = -1;
            delta[userAccount] = volume - delta[userAccount];
        }
        else {
            delta[userAccount] -= volume;
        }
    }
    else {
        delta[userAccount] += volume;
    }
    //unlock
}

void AccountSys::add(UserAccount userAccount, VolumeType volume) {
    //check lock & lock
    if (sign[userAccount] == -1) {
        if (delta[userAccount] < volume) {
            sign[userAccount] = 1;
            delta[userAccount] = volume - delta[userAccount];
        }
        else {
            delta[userAccount] -= volume;
        }
    }
    else {
        delta[userAccount] += volume;
    }
    //unlock
}

bool AccountSys::checkBalance(UserAccount userAccount, VolumeType volume) {
    return deposit[userAccount] + sign[userAccount] * delta[userAccount] - volume >= 0;
}