#include "utils.h"
#include "mbedtls/error.h"
#include <string>

int utils::printf_std(const char *fmt, ...)
{
  int ret;
  va_list ap;
  char buf[BUFSIZ] = {'\0'};
  va_start(ap, fmt);
  vsnprintf(buf, BUFSIZ, fmt, ap);
      va_end(ap);
  ocall_print_to_std(&ret, buf);
  return ret;
}

int utils::printf_err(const char *fmt, ...)
{
  int ret;
  va_list ap;
  char buf[BUFSIZ] = {'\0'};
  va_start(ap, fmt);
  vsnprintf(buf, BUFSIZ, fmt, ap);
      va_end(ap);
  ocall_print_to_err(&ret, buf);
  return ret;
}


std::string utils::mbedtls_error(int ret) {
  if (ret == 0) return "";
  char buffer[1024];
  char buffer2[1024];

  mbedtls_strerror(ret, buffer, sizeof buffer);
  snprintf(buffer2, sizeof buffer2, "Error: %#x. %s", -ret, buffer);

  return std::string(buffer2);
}

std::vector<uint8_t> utils::sgx_unseal_data_cpp(const sgx_sealed_data_t *secret, size_t len) {
  // not used
  (void) len;

  uint32_t unsealed_len = sgx_get_encrypt_txt_len(secret);
  uint8_t y[unsealed_len];
  sgx_status_t st;

  st = sgx_unseal_data(secret, nullptr, nullptr, y, &unsealed_len);
  if (st != SGX_SUCCESS) {
    throw std::runtime_error("unseal returned " + std::to_string(st));
  }

  return std::vector<uint8_t>(y, y + sizeof y);
}
