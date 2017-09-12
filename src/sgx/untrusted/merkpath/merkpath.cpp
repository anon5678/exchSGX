/*
 * Based on Iddo's implementation.
 */

#include "merkpath.h"

#include <cstring>
#include <iomanip>
#include <iostream>
#include <openssl/ripemd.h>
#include <openssl/sha.h>
#include <iostream>

using std::cout;
using std::endl;

std::string base64_encode(const std::string &);
std::string base64_decode(const std::string &);

typedef unsigned long long cointype;
typedef unsigned char arrdigest[SHA256_DIGEST_LENGTH];

int char2int(char c) {
  if(c >= '0' && c <= '9') return c - '0';
  //if(c >= 'A' && c <= 'F') return c - 'A' + 10;
  if(c >= 'a' && c <= 'f') return c - 'a' + 10;
  throw std::invalid_argument("bad hex");
}
void hex2bin(unsigned char* dest, const char* src) {
  while(*src && src[1]) {
    *(dest++) = char2int(*src)*16 + char2int(src[1]);
    src += 2;
  }
}

void hexdump(const unsigned char *data, int len) {
  std::cout << std::hex;
  for (int i = 0; i < len; ++i)
    std::cout << std::setfill('0') << std::setw(2) << (int)data[i];
  std::cout << std::dec << std::endl;
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

// s1+s2 are the 32+32 bytes input, dst is 32 bytes output
void sha256double(void const *const s1, void const *const s2, void *const dst) {
  SHA256_CTX h1, h2;
  unsigned char tmp[SHA256_DIGEST_LENGTH];

  SHA256_Init(&h1);
  // if(NULL != s1)
  SHA256_Update(&h1, (unsigned char *)s1, SHA256_DIGEST_LENGTH);
  // if(NULL != s2)
  SHA256_Update(&h1, (unsigned char *)s2, SHA256_DIGEST_LENGTH);
  SHA256_Final(tmp, &h1);

  SHA256_Init(&h2);
  SHA256_Update(&h2, tmp, SHA256_DIGEST_LENGTH);
  SHA256_Final((unsigned char *)dst, &h2);
}

void hash160(void const *const src, int len, void *const dst) {
  SHA256_CTX h1;
  unsigned char tmp[SHA256_DIGEST_LENGTH];
  SHA256_Init(&h1);
  SHA256_Update(&h1, (unsigned char *)src, len);
  SHA256_Final(tmp, &h1);
  RIPEMD160_CTX h2;
  RIPEMD160_Init(&h2);
  RIPEMD160_Update(&h2, tmp, SHA256_DIGEST_LENGTH);
  RIPEMD160_Final((unsigned char *)dst, &h2);
}

void recursiveMerk(const arrdigest *level, int size, int path) {
  int k = (size + (size & 1)) / 2;
  arrdigest *next = new arrdigest[k];

  for (int i = 0; i < k; ++i) {
    const unsigned char *left_node = level[2 * i];
    const unsigned char *right_node =
        ((2 * i + 1) == size ? left_node : level[2 * i + 1]);
    sha256double(left_node, right_node, next[i]);
    if (path == (2 * i + 1)) {
      std::cout << "L: ";
      hexdump(left_node, SHA256_DIGEST_LENGTH);
      continue;
    }
    if (path == (2 * i)) {
      std::cout << "R: ";
      if (left_node != right_node)
        hexdump(right_node, SHA256_DIGEST_LENGTH);
      else
        std::cout << std::endl;
    }
  }
  if (k > 1)
    recursiveMerk(next, k, path / 2);
  else {
    cout << "root: ";
    byte_swap(next[0], SHA256_DIGEST_LENGTH);
    hexdump(next[0], SHA256_DIGEST_LENGTH);
  }
  delete[] next;
}

void merkGenPathHEX(const vector<string> &leaf_nodes, int index) {
  size_t size = leaf_nodes.size();
  arrdigest *mTree = new arrdigest[size];

  for (int i = 0; i < size; ++i) {
    unsigned char *tmp = mTree[i];
    //std::memcpy(tmp, (base64_decode(leaf_nodes[i])).data(), 32);
    hex2bin(tmp, leaf_nodes[i].c_str());
    // hexdump(tmp, 32);
    byte_swap(tmp, 32);
  }

  if (size > 1)
    recursiveMerk(mTree, size, index);

  delete[] mTree;
}

void merkVerifyPath(const std::string &leaf, const std::string *branch,
                    int dirvec) {
  unsigned char curr[SHA256_DIGEST_LENGTH];
  const char *tmp;

  std::memcpy(curr, (base64_decode(leaf)).data(), 32);
  byte_swap(curr, 32);

  for (int i = 0; dirvec > 1; ++i, dirvec >>= 1) {
    if ((branch[i]).empty()) {
      sha256double(curr, curr, curr);
      continue;
    }
    tmp = (base64_decode(branch[i])).data();
    if (dirvec & 1)
      sha256double(curr, tmp, curr);
    else
      sha256double(tmp, curr, curr);
  }

  byte_swap(curr, 32);
  hexdump(curr, 32);
}

void fill_timelock_payment_template(unsigned char *aa, const char *RTEpk,
                                    int timeout, const char *refund) {
  int j = 0;
  aa[j++] = 0x63; // op_if
  aa[j++] = 0xa8; // op_sha256 (rm)
  aa[j++] = 0x20; // 32 bytes digest size (rm)
  std::memcpy(
      aa + j,
      (base64_decode("x3Xnt1ft5jDNCqERO9ECZhqziCnKUqZCKreChi8mhkY=")).data(),
      32);           // sha256 digest (rm)
  aa[j + 32] = 0x88; // op_equalverify (rm)
  j += 33;
  aa[j++] = 0x21; // 33 bytes pubkey size
  std::memcpy(aa + j, RTEpk, 33);
  aa[j + 33] = 0xAC; // op_checksig
  j += 34;
  aa[j++] = 0x67; // op_else
  aa[j++] = 0x3;  // timeout size
  aa[j++] = timeout >> 16;
  aa[j++] = timeout >> 8;
  aa[j++] = timeout;
  aa[j++] = 0xb1; // op_CLTV
  aa[j++] = 0x75; // op_drop
  aa[j++] = 0x21; // 33 bytes pubkey size
  std::memcpy(aa + j, refund, 33);
  aa[j + 33] = 0xAC; // op_checksig
  aa[j + 34] = 0x68; // op_endif
}

cointype validateDeposit(const unsigned char *tx, const char *RTEpubkey,
                         int timeout, const char *refund) {
  if (1 != tx[4])
    return 0;                                      // single input
  int j = 5 + 32 + 4 + 1 + tx[5 + 32 + 4] + 4 + 1; // skip to first output
  cointype r = tx[j++];
  for (int i = 8; i <= 56; i += 8)
    r += cointype(tx[j++]) << i;
  if (23 != tx[j++])
    return 0; // p2sh size
  if (0xA9 != tx[j++])
    return 0; // op_hash160
  if (0x14 != tx[j++])
    return 0; // 20 bytes
  if (0x87 != tx[j + 20])
    return 0; // op_equal
  hexdump(tx + j, 20);

  unsigned char arr[114];
  fill_timelock_payment_template(arr, RTEpubkey, timeout, refund);
  unsigned char res[20];
  hash160(arr, 114, res);
  hexdump(res, 20);

  return r;
}

#if 0
int main() {
#include "txdata/tx390580base64.txt"
   merkGenPath(leaves390580,1182,664);

   /* unsigned char arr288bcaaa[223]; */
   /* std::memcpy(arr288bcaaa, (base64_decode(txin288bcaaa)).data(), 223); */
   /* //byte_swap(arr288bcaaa, 223); */

   /* SHA256_CTX h1,h2; */
   /* unsigned char t1[SHA256_DIGEST_LENGTH]; */
   /* SHA256_Init(&h1); */
   /* SHA256_Update(&h1, arr288bcaaa, 223); */
   /* SHA256_Final(t1, &h1); */
   /* SHA256_Init(&h2); */
   /* SHA256_Update(&h2, t1, SHA256_DIGEST_LENGTH); */
   /* SHA256_Final(t1, &h2); */

   /* byte_swap(t1, 32); */
   /* hexdump(t1, 32); */

   /* const cointype amount = validateDeposit(arr288bcaaa, */
   /*    base64_decode("A9fGBSVEvELrK8DSfIhAFq25M/FVdqGi0hzU3Q8t4MN9").data(), */
   /*    0x389900, */
   /*    base64_decode("AhhEmJor16zRJ91+1Rqi9NVbMtu0FN5jJa434FwQZ1mN").data()); */
   /* std::cout << amount << std::endl; */

   return 0;
}
#endif
