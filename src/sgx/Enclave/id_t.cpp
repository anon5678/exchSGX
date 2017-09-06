//
// Created by fanz on 9/6/17.
//

#include "id_t.h"
#include "hybrid_cipher.h"

#include "log.h"
#include "pprint.h"

int provision_rsa_id(const unsigned char *encrypted_rsa_id, size_t buf_len) {
  HybridCipher cipher(encrypted_rsa_id, buf_len);

  HybridEncryption dec_ctx;
  try {
    vector<uint8_t> clear_txt = dec_ctx.hybridDecrypt(cipher);

    hexdump("clear txt", clear_txt.data(), clear_txt.size());
    return 0;
  }
  catch (const std::exception& e) {
    return -1;
    LL_CRITICAL("%s", e.what());
  }
  catch (...) {
    return -1;
    LL_CRITICAL("unknown error");
  }
}