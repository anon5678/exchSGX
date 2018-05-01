//
// Created by lilione on 2018/3/30.
//

#ifndef EXCHSGX_COPY_VALUEPROOF_H
#define EXCHSGX_COPY_VALUEPROOF_H

#endif //EXCHSGX_COPY_VALUEPROOF_H

#include "AccountProof.h"
#include "ContentProof.h"

class ValueProof{
public:
    AccountProof accountProof;
    ContentProof contentProof;

    ValueProof(AccountProof accountProof, ContentProof contentProof):
        accountProof(accountProof), contentProof(contentProof) {}
};
