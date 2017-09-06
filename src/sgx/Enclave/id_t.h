//
// Created by fanz on 9/6/17.
//

#ifndef PROJECT_ID_T_H
#define PROJECT_ID_T_H

#include <stddef.h>

#if defined(__cplusplus)
extern "C" {
#endif

int provision_rsa_id(const unsigned char *encrypted_rsa_id, size_t buf_len);

#if defined(__cplusplus)
}
#endif

#endif //PROJECT_ID_T_H
