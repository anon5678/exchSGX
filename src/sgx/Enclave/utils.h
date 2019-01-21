#ifndef PROJECT_ENCLVAE_UTILS_H
#define PROJECT_ENCLAVE_UTILS_H

#include "Enclave_t.h"

#include <cstdio>
#include <cstdint>
#include <string>
#include <vector>

#define ECALL_WRAPPER_RET(expr) \
  try { expr; return 0; }                          \
  catch (const std::exception & e) { LL_CRITICAL("error happened: %s", e.what()); return -1; }\
  catch (...) { LL_CRITICAL("unknown error happened"); return -1; }

#define CATCH_STD_AND_ALL \
  catch (const std::exception & e) { LL_CRITICAL("error happened: %s", e.what()); return -1; }\
  catch (...) { LL_CRITICAL("unknown error happened"); return -1; }

#define CATCHALL_AND(x) \
  catch (const std::exception & e) { LL_CRITICAL("error happened: %s", e.what()); (x); }\
  catch (...) { LL_CRITICAL("unknown error happened"); (x); }

#define CATCH_STD_AND_ALL_NO_RET \
  catch (const std::exception & e) { LL_CRITICAL("error happened: %s", e.what()); }\
  catch (...) { LL_CRITICAL("unknown error happened"); }

using bytes = std::vector<uint8_t>;

#ifdef __cplusplus
extern "C" {
#endif

int printf_std(const char *fmt, ...);
int printf_err(const char *fmt, ...);

#ifdef __cplusplus
};
#endif

namespace utils {
using std::string;
using std::vector;

string mbedtls_error(int ret);
vector<uint8_t> sgx_unseal_data_cpp(const sgx_sealed_data_t *secret, size_t len);
} //namespace
#endif //PROJECT_UTILS_H
