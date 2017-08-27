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