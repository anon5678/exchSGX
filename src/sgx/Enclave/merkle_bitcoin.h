//
// Created by fanz on 9/20/17.
//

#ifndef PROJECT_MERKLE_BITCOIN_H
#define PROJECT_MERKLE_BITCOIN_H

#include "../common/merkle_data.h"

#ifdef __cplusplus
extern "C" {
#endif

int merkle_proof_verify(const char *root, const merkle_proof_t *proof);
#ifdef __cplusplus
}
#endif

#endif //PROJECT_MERKLE_H
