#include "securechannel.h"

using namespace std;

// ecall
size_t nacl_keygen_in_seal(unsigned char *o_sealed, size_t cap_sealed_buf, unsigned char *o_pubkey) {
  try {
    string sk;
    string pk = nacl_crypto_box_keypair(&sk);

    // seal the data
    size_t sealed_len = 0;
    sealed_len = sgx_calc_sealed_data_size(0, sk.size());
    if (sealed_len > cap_sealed_buf) {
      LL_CRITICAL("buffer too small");
      return -1;
    }

    auto *seal_buffer = (sgx_sealed_data_t *) malloc(sealed_len);

    auto st = sgx_seal_data(0, nullptr, sk.size(), (const unsigned char *) sk.data(), sealed_len, seal_buffer);
    if (st != SGX_SUCCESS) {
      LL_LOG("Failed to seal. Ecall returned %d", st);
      free(seal_buffer);
      return -1;
    }

    memcpy(o_sealed, seal_buffer, sealed_len);
    free(seal_buffer);

    memcpy(o_pubkey, (const unsigned char*) pk.data(), pk.size());

    return sealed_len;
  }

  CATCH_STD_AND_ALL
}
