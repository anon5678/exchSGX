//
// Created by fanz on 8/27/17.
//

#include "utils.h"

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

#include "mbedtls/error.h"
#include <string>

std::string utils::mbedtls_error(int ret) {
  if (ret == 0) return "";
  char buffer[1024];
  char buffer2[1024];

  mbedtls_strerror(ret, buffer, sizeof buffer);
  snprintf(buffer2, sizeof buffer2, "Error: %#x. %s", -ret, buffer);

  return std::string(buffer2);
}

