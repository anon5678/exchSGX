#ifndef MBEDTLS_SGX_ENC_H
#define MBEDTLS_SGX_ENC_H

#include <sgx_tseal.h>

#include <mbedtls/ctr_drbg.h>
#include <mbedtls/entropy.h>
#include <mbedtls/config.h>
#include <mbedtls/platform.h>
#include <mbedtls/error.h>
#include <mbedtls/debug.h>
#include <mbedtls/bignum.h>
#include <mbedtls/ecdh.h>
#include <mbedtls/ecp.h>
#include <mbedtls/gcm.h>

#include <string.h>

#include <exception>
#include <vector>
#include <string>

using namespace std;

typedef uint8_t AESKey[32];
typedef uint8_t AESIv[32];
typedef uint8_t GCMTag[16];
typedef uint8_t ECPointBuffer[65];

/*
 * ECALL interface
 */
#if defined(__cplusplus)
extern "C" {
#endif

int provision_hybrid_key(const sgx_sealed_data_t *secret, size_t secret_len);
int get_hybrid_pubkey(ECPointBuffer pubkey);

#if defined(__cplusplus)
}
#endif

#define PREDEFINED_HYBRID_SECKEY "cd244b3015703ddf545595da06ada5516628c5feadbf49dc66049c4b370cc5d8"

#define CHECK_RET(ret) do { if (ret != 0) { throw runtime_error(err(ret)); }} while (0);
#define CHECK_RET_GO(ret, label) do { if (ret != 0) { goto label; }} while (0);

#define DEBUG_BUFFER(title, buf, len) do { \
  mbedtls_debug_print_buf(&dummy_ssl_ctx, 0, __FILE__,__LINE__, title, buf, len); } \
 while (0);

static void my_debug(void *ctx, int level, const char *file, int line,
                     const char *str) {
  (void) ctx;
  (void) level;

  mbedtls_printf("%s:%d: %s", file, line, str);
}


class HybridCipher {
 public:
  static const size_t USER_PUBKEY_LEN = sizeof(ECPointBuffer);
  static const size_t AES_IV_LEN = sizeof(AESIv);
  static const size_t GCM_TAG_LEN = sizeof(GCMTag);
  static const size_t HEADER_LEN = USER_PUBKEY_LEN + AES_IV_LEN + GCM_TAG_LEN;

  ECPointBuffer user_pubkey;
  AESIv aes_iv;
  GCMTag gcm_tag;
  vector <uint8_t> data;

  HybridCipher() = default;
  HybridCipher(const vector<uint8_t>& out);
  HybridCipher(const unsigned char* cipher, size_t len);
  vector<uint8_t> toBytes();
  string toBase64();
  string toString();
};


class HybridEncryption {
 public:
  static const mbedtls_ecp_group_id EC_GROUP = MBEDTLS_ECP_DP_SECP256K1;
  static const AESIv iv;
  static const size_t PUBLIC_KEY_SIZE = 65;

  // public utility functions
  static int secretToPubkey(const mbedtls_mpi *seckey, ECPointBuffer pubkey);
  static void queryPubkey(ECPointBuffer pubkey);

  // methods
  HybridEncryption();
  HybridCipher hybridEncrypt(const uint8_t *tc_pubkey, const uint8_t *data, size_t data_len);
  vector <uint8_t> hybridDecrypt(const HybridCipher &ciphertext);

 private:
  // general setup
  int ret;
  uint8_t buf[100];
  char err_msg[1024];

  // rng setup
  mbedtls_ctr_drbg_context ctr_drbg;
  mbedtls_entropy_context entropy;

  // only used for debugging
  mbedtls_ssl_context dummy_ssl_ctx;
  mbedtls_ssl_config dummy_ssl_cfg;

  void storePubkey(const mbedtls_ecp_group *grp, const mbedtls_ecp_point *p, ECPointBuffer buf);
  void loadPubkey(const mbedtls_ecp_group *grp, mbedtls_ecp_point *p, const uint8_t *buf);
  const char *err(int err);

  void hybridEncrypt(const ECPointBuffer tc_pubkey,
                     const AESIv aes_iv,
                     const uint8_t *data,
                     size_t data_len,
                     HybridCipher &ciphertext);

  void aes_gcm_256_enc(const AESKey aesKey, const AESIv iv,
                       const uint8_t *data, size_t data_len,
                       GCMTag tag, vector <uint8_t> &cipher);

  void aes_gcm_256_dec(const AESKey aesKey, const AESIv iv,
                       const uint8_t *ciphertext, size_t ciphertext_len,
                       const GCMTag tag, uint8_t *cleartext);

};

class DecryptionException: public std::exception {
 private:
  const string reason;
 public:
  DecryptionException(string reason): reason(reason) {}
  const char* what() const throw() { return reason.c_str(); }
};

#endif //MBEDTLS_SGX_ENC_H
