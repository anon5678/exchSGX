#ifndef EXCH_FAIRNESS_UNTRUSTED_H
#define EXCH_FAIRNESS_UNTRUSTED_H

#include "Enclave_u.h"

#if __cplusplus
extern "C" {
#endif

void sendMessagesToFairnessFollowers();
void settle();

#if __cplusplus
};
#endif

#endif
