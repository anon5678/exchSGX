//
// Created by fanz on 9/20/17.
//

#ifndef PROJECT_PORTABLE_H
#define PROJECT_PORTABLE_H

#ifdef IN_ENCLAVE
extern "C" int printf_sgx(const char *fmt, ...);
#else
#include <stdio.h>
#define printf_sgx printf
#endif

#endif //PROJECT_PORTABLE_H
