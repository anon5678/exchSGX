#ifndef NACL_CRYPTO_BOX_H
#define NACL_CRYPTO_BOX_H

#include <string>

extern "C" {
#include "tweetnacl.h"
}

std::string nacl_crypto_box_keypair(std::string *sk_string);
std::string nacl_crypto_box(const std::string &m, const std::string &n, const std::string &pk, const std::string &sk);
std::string nacl_crypto_box_open(const std::string &c, const std::string &n, const std::string &pk, const std::string &sk);

#endif //PROJECT_CRYPTO_BOX_H
