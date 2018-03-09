#include <sgx_trts.h>

typedef unsigned char u8;
typedef unsigned long u32;
typedef unsigned long long u64;
typedef long long i64;
typedef i64 gf[16];

void randombytes(u8 * dest,u64 len) {
  sgx_status_t st = sgx_read_rand(dest, len);
  if (st != SGX_SUCCESS) return;
}
