#ifndef BASE64_HXX
#define BASE64_HXX

#include <stdint.h>

#include <vector>
#include <string>

namespace ext {

// encoding
int b64_ntop(unsigned char const *src, size_t srclength, char *target, size_t targsize);
std::string b64_encode(const unsigned char *src, size_t src_len);

// decoding
int b64_pton(const char *src, unsigned char*target, size_t targsize);
std::vector<unsigned char> b64_decode(const std::string &in);
}

#endif /* BASE64_HXX */
