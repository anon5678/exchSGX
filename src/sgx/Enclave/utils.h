//
// Created by fanz on 8/27/17.
//

#ifndef PROJECT_UTILS_H
#define PROJECT_UTILS_H

#include "Enclave_t.h"

#include <cstdio>
#include <string>

namespace utils {

int printf_std(const char *fmt, ...);
int printf_err(const char *fmt, ...);
std::string mbedtls_error(int ret);

}
#endif //PROJECT_UTILS_H
