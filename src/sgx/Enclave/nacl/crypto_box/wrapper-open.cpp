#include <string>
using std::string;
using std::runtime_error;
#include "crypto_box.h"

string nacl_crypto_box_open(const string &c,const string &n,const string &pk,const string &sk)
{
  if (pk.size() != crypto_box_PUBLICKEYBYTES) throw runtime_error("incorrect public-key length");
  if (sk.size() != crypto_box_SECRETKEYBYTES) throw runtime_error("incorrect secret-key length");
  if (n.size() != crypto_box_NONCEBYTES) throw runtime_error("incorrect nonce length");
  size_t clen = c.size() + crypto_box_BOXZEROBYTES;
  unsigned char cpad[clen];
  for (int i = 0;i < crypto_box_BOXZEROBYTES;++i) cpad[i] = 0;
  for (auto i = crypto_box_BOXZEROBYTES;i < clen;++i) cpad[i] = c[i - crypto_box_BOXZEROBYTES];
  unsigned char mpad[clen];
  if (crypto_box_open(mpad,cpad,clen,
                       (const unsigned char *) n.c_str(),
                       (const unsigned char *) pk.c_str(),
                       (const unsigned char *) sk.c_str()
                     ) != 0)
    throw runtime_error("ciphertext fails verification");
  if (clen < crypto_box_ZEROBYTES)
    throw runtime_error("ciphertext too short"); // should have been caught by _open
  return string(
    (char *) mpad + crypto_box_ZEROBYTES,
    clen - crypto_box_ZEROBYTES
  );
}
