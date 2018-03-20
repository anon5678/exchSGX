//
// Created by fanz on 9/20/17.
//

#ifndef PROJECT_PORTABLE_H
#define PROJECT_PORTABLE_H

#ifdef IN_ENCLAVE
#include "../Enclave/utils.h"
#define printf_sgx utils::printf_std
#else
#include <stdio.h>
#define printf_sgx printf
#endif

#endif //PROJECT_PORTABLE_H
