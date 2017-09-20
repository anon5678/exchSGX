//
// Created by fanz on 9/20/17.
//

#include "utils.h"
#include <stdexcept>

int char2int(char c) {
  if (c >= '0' && c <= '9') return c - '0';
  //if(c >= 'A' && c <= 'F') return c - 'A' + 10;
  if (c >= 'a' && c <= 'f') return c - 'a' + 10;
  throw std::invalid_argument("bad hex");
}

void hex2bin(unsigned char *dest, const char *src) {
  while (*src && src[1]) {
    *(dest++) = char2int(*src) * 16 + char2int(src[1]);
    src += 2;
  }
}

void byte_swap(unsigned char *data, int len) {
  unsigned char tmp[len];
  int c = 0;
  while (c < len) {
    tmp[c] = data[len - (c + 1)];
    c++;
  }
  c = 0;
  while (c < len) {
    data[c] = tmp[c];
    c++;
  }
}

#ifdef IN_ENCLAVE
extern "C" int printf_sgx(const char *fmt, ...);
#else
#include <stdio.h>
#define printf_sgx printf
#endif

void hd(const char *title, void const *data, size_t len)
{
  unsigned int i;
  unsigned int r,c;

  if (!data)
    return;

  printf_sgx("%s\n", title);

  for (r=0,i=0; r<(len/16+(len%16!=0)); r++,i+=16)
  {
    printf_sgx("0x%04X:   ",i); /* location of first byte in line */

    for (c=i; c<i+8; c++) /* left half of hex dump */
      if (c<len)
        printf_sgx("%02X ",((unsigned char const *)data)[c]);
      else
        printf_sgx("   "); /* pad if short line */

    printf_sgx("  ");

    for (c=i+8; c<i+16; c++) /* right half of hex dump */
      if (c<len)
        printf_sgx("%02X ",((unsigned char const *)data)[c]);
      else
        printf_sgx("   "); /* pad if short line */

    printf_sgx("   ");

    for (c=i; c<i+16; c++) /* ASCII dump */
      if (c<len)
        if (((unsigned char const *)data)[c]>=32 &&
            ((unsigned char const *)data)[c]<127)
          printf_sgx("%c",((char const *)data)[c]);
        else
          printf_sgx("."); /* put this for non-printables */
      else
        printf_sgx(" "); /* pad if short line */

    printf_sgx("\n");
  }
}
