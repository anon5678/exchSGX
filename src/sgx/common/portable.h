#ifndef PROJECT_PORTABLE_H
#define PROJECT_PORTABLE_H

#ifdef IN_ENCLAVE
#include "../Enclave/utils.h"
#define printf_sgx printf_std
#else
#include <stdio.h>
#define printf_sgx printf
#endif

#endif //PROJECT_PORTABLE_H
