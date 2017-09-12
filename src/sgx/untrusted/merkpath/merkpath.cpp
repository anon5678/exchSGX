#include "merkpath.h"

#include <cstring>
#include <iomanip>
#include <iostream>
#include <openssl/ripemd.h>
#include <openssl/sha.h>
#include <iostream>

using std::cout;
using std::endl;

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

void recursiveMerk(const arrdigest *level, int size, int path,
                   int dirvec, int position) {
  int k = (size + (size & 1)) / 2;
  arrdigest *next = new arrdigest[k];

  for (int i = 0; i < k; ++i) {
    const unsigned char *left_node = level[2 * i];
    const unsigned char *right_node =
        ((2 * i + 1) == size ? left_node : level[2 * i + 1]);
    sha256double(left_node, right_node, next[i]);
    if (path == (2 * i + 1)) {
      //std::cout << "L: ";
      hexdump(left_node, SHA256_DIGEST_LENGTH);
      continue;
    }
    if (path == (2 * i)) {
      //std::cout << "R: ";
      if (left_node != right_node) {
        hexdump(right_node, SHA256_DIGEST_LENGTH);
        dirvec |= (1 << position);
      }
      else
        std::cout /* << "*" */ << std::endl;
    }
  }
  if (k > 1)
    recursiveMerk(next, k, path / 2, dirvec, position+1);
  else {
    cout << (dirvec | (1 << (position+1))) << endl;
    cout << "--- merkGenPathHEX END ---" << endl;
    //cout << "root: ";
    byte_swap(next[0], SHA256_DIGEST_LENGTH);
    hexdump(next[0], SHA256_DIGEST_LENGTH);
  }
  delete[] next;
}

void merkGenPathHEX(const vector<string> &leaf_nodes, int index) {
  size_t size = leaf_nodes.size();
  if (size <= 1) throw;
  arrdigest *mTree = new arrdigest[size];

  for (int i = 0; i < size; ++i) {
    unsigned char *tmp = mTree[i];
    //std::memcpy(tmp, (base64_decode(leaf_nodes[i])).data(), 32);
    hex2bin(tmp, leaf_nodes[i].c_str());
    // hexdump(tmp, 32);
    byte_swap(tmp, 32);
  }

  cout << "--- merkGenPathHEX START ---" << endl;
  recursiveMerk(mTree, size, index, 0, 0);
  delete[] mTree;
}

void merkVerifyPathHEX(const std::string &leaf, const std::string *branch,
                       int dirvec) {
  unsigned char curr[SHA256_DIGEST_LENGTH];
  unsigned char tmp[SHA256_DIGEST_LENGTH];

  //std::memcpy(curr, (base64_decode(leaf)).data(), 32);
  hex2bin(curr, leaf.c_str());
  byte_swap(curr, 32);

  for (int i = 0; dirvec > 1; ++i, dirvec >>= 1) {
    if ((branch[i]).empty()) {
      sha256double(curr, curr, curr);
      continue;
    }
    //std::memcpy(tmp, (base64_decode(branch[i])).data(), 32);
    hex2bin(tmp, branch[i].c_str());
    if (dirvec & 1)
      sha256double(curr, tmp, curr);
    else
      sha256double(tmp, curr, curr);
  }

  byte_swap(curr, 32);
  hexdump(curr, 32);
}

#if 0
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
#endif

#ifdef DBGMERK
void testMerk() {
  // b42be2d0403e5a7336b1f5e2b5c344827177d191b1cbced3565b7ba138d8a83d
  const std::vector<std::string> inp1 {
         "1141217f7db1bd3f3d098310e6f707eb249736cdf31ce3400705fa72bbc524f0",
         "a3f83c7f6e77ce74c978b3d42fd46a38863fb1f8170feb162382e634e9fd4336",
         "65650a7ab3da07409fa7833958f83df9327f02bd3f703322b7b973935c2c08f1",
         "a0819a177c89b04e3bbb2710e2d89007da32f09f705718cb9e85a7dcc464e3e6",
         "585ae7e330f29a13ddeca437c948489de8d885fec32684f2131d24cd854a0593"};
  const std::string path1[3] = {
         "e6e364c4dca7859ecb1857709ff032da0790d8e21027bb3b4eb0897c179a81a0",
	 "396d16d4747f871a1528a0425f9db4023a49aa9dba3345decd8fbee0180f472f",
         "a3b4fb0ca4f26695bd61b5835458d9c9f4bfb75602c2173211e19eb2f0bcb29d"};
  const std::string path2[3] = {std::string(), std::string(),
         "10b038ab01c5f4048ebe7b4b66def9725dbd29d6f571474ac0c95949f74113d3"};
  merkGenPathHEX(inp1, 2);
  merkVerifyPathHEX(inp1[2], path1, 13 /* 1RLR=1101 */);
  merkVerifyPathHEX(inp1[4], path2, 8 /* 1Lxx=10xx */);
}
#endif

