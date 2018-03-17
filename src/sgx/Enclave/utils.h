#ifndef PROJECT_ENCLVAE_UTILS_H
#define PROJECT_ENCLAVE_UTILS_H

#include "Enclave_t.h"

#include <cstdio>
#include <cstdint>
#include <string>
#include <vector>

using bytes = std::vector<uint8_t>;

namespace utils {
using std::string;
using std::vector;

int printf_std(const char *fmt, ...);
int printf_err(const char *fmt, ...);
string mbedtls_error(int ret);
vector<uint8_t> sgx_unseal_data_cpp(const sgx_sealed_data_t *secret, size_t len);
} //namespace
#endif //PROJECT_UTILS_H
