#include "hybrid_cipher.h"

#include <sgx_tseal.h>

#include "mbedtls/bignum.h"
#include "log.h"
#include "pprint.h"

#include "../common/errno.h"
#include "../common/base64.hxx"

using namespace std;

static mbedtls_mpi g_secret_hybrid_key;

int provision_hybrid_key(const sgx_sealed_data_t *secret, size_t secret_len) {
  // used by edge8r
  (void) secret_len;

  uint32_t decrypted_text_length = sgx_get_encrypt_txt_len(secret);
  uint8_t y[decrypted_text_length];
  sgx_status_t st;

  st = sgx_unseal_data(secret, nullptr, nullptr, y, &decrypted_text_length);
  if (st != SGX_SUCCESS) {
    LL_CRITICAL("unseal returned %#x", st);
    return -1;
  }

  // initialize the global secret key
  mbedtls_mpi_init(&g_secret_hybrid_key);
  return mbedtls_mpi_read_binary(&g_secret_hybrid_key, y, sizeof y);
}

int get_hybrid_pubkey(ECPointBuffer pubkey) {
  try {
    HybridEncryption::queryPubkey(pubkey);
    return 0;
  }
  catch (const exception& e) {
    LL_CRITICAL("%s", e.what());
    return 1;
  }
  catch (...) {
    LL_CRITICAL("unknown error");
    return 1;
  }
}

const AESIv HybridEncryption::iv = {0x99};

void HybridEncryption::storePubkey(const mbedtls_ecp_group *grp, const mbedtls_ecp_point *p, ECPointBuffer buf) {
  size_t olen;
  int ret = mbedtls_ecp_point_write_binary(grp, p, MBEDTLS_ECP_PF_UNCOMPRESSED, &olen, buf, PUBLIC_KEY_SIZE);
  if (ret != 0 || olen != PUBLIC_KEY_SIZE) {
    throw runtime_error("mbedtls_ecp_point_write_binary failed");
  }
}

void HybridEncryption::loadPubkey(const mbedtls_ecp_group *grp, mbedtls_ecp_point *p, const uint8_t *buf) {
  int ret = mbedtls_ecp_point_read_binary(grp, p, buf, PUBLIC_KEY_SIZE);
  if (ret != 0) {
    throw runtime_error("mbedtls_ecp_point_read_binary failed");
  }
}

const char *HybridEncryption::err(int err) {
  mbedtls_strerror(err, err_msg, sizeof err_msg);
  return err_msg;
}

HybridEncryption::HybridEncryption() {
  ret = 0;

  mbedtls_ctr_drbg_init(&ctr_drbg);
  mbedtls_entropy_init(&entropy);
  ret = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy,
                              (const unsigned char *) "RANDOM_GEN", 10);

  if (ret != 0) {
    mbedtls_printf("failed in mbedtls_ctr_drbg_seed: %d\n", ret);
    mbedtls_strerror(ret, err_msg, sizeof err_msg);
    throw runtime_error(err_msg);
  }

  mbedtls_ctr_drbg_set_prediction_resistance(&ctr_drbg,
                                             MBEDTLS_CTR_DRBG_PR_OFF);

  // debugging setup
  mbedtls_ssl_init(&dummy_ssl_ctx);
  mbedtls_ssl_config_init(&dummy_ssl_cfg);
  mbedtls_ssl_conf_dbg(&dummy_ssl_cfg, my_debug, nullptr);
  if ((ret = mbedtls_ssl_setup(&dummy_ssl_ctx, &dummy_ssl_cfg)) != 0) {
    LL_CRITICAL("failed to setup ssl: %d", ret);
  };

  mbedtls_debug_set_threshold(-1);
}


void HybridEncryption::queryPubkey(ECPointBuffer pubkey) {
#ifdef PREDEFINED_HYBRID_SECKEY
  LL_CRITICAL("*** PREDEFINED SECRET KEY IS USED ***");
  LL_CRITICAL("*** DISABLE THIS BEFORE DEPLOY ***");
  int ret = mbedtls_mpi_read_string(&g_secret_hybrid_key, 16, PREDEFINED_HYBRID_SECKEY);
  if (ret != 0) {
    LL_CRITICAL("Error: mbedtls_mpi_read_string returned %d", ret);
    return;
  }
#else
  if (g_secret_hybrid_key.p == NULL) {
    LL_CRITICAL("key not provisioned yet");
    throw std::runtime_error("key not provisioned yet");
  }
#endif
  HybridEncryption::secretToPubkey(&g_secret_hybrid_key, pubkey);
}

vector<uint8_t> HybridEncryption::hybridDecrypt(const HybridCipher &ciphertext) {
  if (g_secret_hybrid_key.p == nullptr) {
    throw runtime_error("hybrid key not provisioned yet. Run queryPubkey() first");
  }

  mbedtls_ecdh_context ctx_tc;
  mbedtls_ecdh_init(&ctx_tc);

  // load the group
  ret = mbedtls_ecp_group_load(&ctx_tc.grp, EC_GROUP);
  if (ret != 0) {
    mbedtls_printf(" failed\n  ! mbedtls_ecp_group_load returned %d\n", ret);
    throw runtime_error(err(ret));
  }

  // 1. load the sec key
  mbedtls_mpi_copy(&ctx_tc.d, &g_secret_hybrid_key);

  // 2. load user's public key
  loadPubkey(&ctx_tc.grp, &ctx_tc.Qp, ciphertext.user_pubkey);

  // 3. compute the shared secret
  ret = mbedtls_ecdh_compute_shared(&ctx_tc.grp, &ctx_tc.z,
                                    &ctx_tc.Qp, &ctx_tc.d,
                                    mbedtls_ctr_drbg_random, &ctr_drbg);
  if (ret != 0) {
    mbedtls_printf(" failed\n  ! mbedtls_ecdh_compute_shared returned %d\n", ret);
    throw runtime_error(err(ret));
  }

  mbedtls_debug_print_mpi(&dummy_ssl_ctx, 0, __FILE__, __LINE__, "derived secret", &ctx_tc.z);

  AESKey aes_key;
  mbedtls_mpi_write_binary(&ctx_tc.z, aes_key, sizeof(AESKey));

  vector<uint8_t> cleartxt;
  // clear text always has the same size as the ciphertext.data
  cleartxt.resize(ciphertext.data.size());
  aes_gcm_256_dec(aes_key, ciphertext.aes_iv,
                  &ciphertext.data[0], ciphertext.data.size(),
                  ciphertext.gcm_tag, &cleartxt[0]);
}

HybridCipher HybridEncryption::hybridEncrypt(const ECPointBuffer tc_pubkey, const uint8_t *data, size_t data_len) {
  HybridCipher ciphertext;
  this->hybridEncrypt(tc_pubkey, iv, data, data_len, ciphertext);

  return ciphertext;
}

void HybridEncryption::hybridEncrypt(const ECPointBuffer tc_pubkey,
                                     const AESIv aes_iv,
                                     const uint8_t *data,
                                     size_t data_len,
                                     HybridCipher &ciphertext) {
  mbedtls_ecdh_context ctx_user;
  mbedtls_ecdh_init(&ctx_user);

  // load the group
  ret = mbedtls_ecp_group_load(&ctx_user.grp, EC_GROUP);
  CHECK_RET_GO(ret, cleanup);

  // generate an ephemeral key
  ret = mbedtls_ecdh_gen_public(&ctx_user.grp, &ctx_user.d, &ctx_user.Q,
                                mbedtls_ctr_drbg_random, &ctr_drbg);
  CHECK_RET_GO(ret, cleanup);

  storePubkey(&ctx_user.grp, &ctx_user.Q, ciphertext.user_pubkey);

  // populate with the tc public key
  ret = mbedtls_mpi_lset(&ctx_user.Qp.Z, 1);
  CHECK_RET_GO(ret, cleanup);
  loadPubkey(&ctx_user.grp, &ctx_user.Qp, tc_pubkey);

  // derive shared secret
  ret = mbedtls_ecdh_compute_shared(&ctx_user.grp, &ctx_user.z,
                                    &ctx_user.Qp, &ctx_user.d,
                                    NULL, NULL);
  CHECK_RET_GO(ret, cleanup);

  mbedtls_debug_print_mpi(&dummy_ssl_ctx, 0, __FILE__, __LINE__, "derived secret", &ctx_user.z);

  // load aes key
  AESKey aes_key;
  mbedtls_mpi_write_binary(&ctx_user.z, aes_key, sizeof(AESKey));

  DEBUG_BUFFER("clear text", data, data_len);
  DEBUG_BUFFER("aes key", aes_key, sizeof(AESKey));

  ciphertext.data.clear();
  ciphertext.data.reserve(data_len);
  aes_gcm_256_enc(aes_key, aes_iv, data, data_len, ciphertext.gcm_tag, ciphertext.data);

  memcpy(ciphertext.aes_iv, aes_iv, sizeof(AESIv));

  DEBUG_BUFFER("cipher", &ciphertext.data[0], ciphertext.data.size());

cleanup:
  mbedtls_ecdh_free(&ctx_user);
  if (ret) throw runtime_error(err(ret));
}

void HybridEncryption::aes_gcm_256_enc(const AESKey aesKey,
                                       const AESIv iv,
                                       const uint8_t *data,
                                       size_t data_len,
                                       GCMTag tag,
                                       vector<uint8_t> &cipher) {
  mbedtls_gcm_context ctx;
  mbedtls_gcm_init(&ctx);

  mbedtls_gcm_setkey(&ctx, MBEDTLS_CIPHER_ID_AES, aesKey, 8 * sizeof(AESKey));

  uint8_t _cipher[data_len];
  ret = mbedtls_gcm_crypt_and_tag(&ctx, MBEDTLS_GCM_ENCRYPT, data_len,
                                  iv, sizeof(AESIv),
                                  NULL, 0,
                                  data,
                                  _cipher, sizeof(GCMTag), tag);

  cipher.insert(cipher.begin(), _cipher, _cipher + data_len);
  mbedtls_gcm_free(&ctx);
  CHECK_RET(ret);
}

void HybridEncryption::aes_gcm_256_dec(const AESKey aesKey,
                                       const AESIv iv,
                                       const uint8_t *ciphertext,
                                       size_t ciphertext_len,
                                       const GCMTag tag,
                                       uint8_t *cleartext) {
  mbedtls_gcm_context ctx;
  mbedtls_gcm_init(&ctx);

  mbedtls_gcm_setkey(&ctx, MBEDTLS_CIPHER_ID_AES, aesKey, 8 * sizeof(AESKey));

  ret = mbedtls_gcm_auth_decrypt(&ctx, ciphertext_len,
                                 iv, sizeof(AESIv),
                                 NULL, 0,
                                 tag, sizeof(GCMTag),
                                 ciphertext, cleartext);
  mbedtls_gcm_free(&ctx);
  CHECK_RET(ret);
}

int HybridEncryption::secretToPubkey(const mbedtls_mpi *seckey, ECPointBuffer pubkey) {
  if (seckey == NULL) {
    return -1;
  }

  mbedtls_ecdsa_context ctx;
  unsigned char __pubkey[65];
  size_t buflen = 0;
  int ret;

  mbedtls_ecdsa_init(&ctx);
  mbedtls_ecp_group_load(&ctx.grp, EC_GROUP);

  mbedtls_mpi_copy(&ctx.d, seckey);

  ret = mbedtls_ecp_mul(&ctx.grp, &ctx.Q, &ctx.d, &ctx.grp.G, NULL, NULL);
  if (ret != 0) {
    LL_CRITICAL("Error: mbedtls_ecp_mul returned %d", ret);
    return -1;
  }

  ret = mbedtls_ecp_point_write_binary(&ctx.grp, &ctx.Q, MBEDTLS_ECP_PF_UNCOMPRESSED, &buflen, __pubkey, 65);
  if (ret == MBEDTLS_ERR_ECP_BUFFER_TOO_SMALL) {
    LL_CRITICAL("buffer too small");
    return -1;
  } else if (ret == MBEDTLS_ERR_ECP_BAD_INPUT_DATA) {
    LL_CRITICAL("bad input data");
    return -1;
  }
  if (buflen != 65) {
    LL_CRITICAL("ecp serialization is incorrect olen=%ld", buflen);
  }

  // copy to user space
  memcpy(pubkey, __pubkey, 65);
  return 0;
}

HybridCipher::HybridCipher(const vector<uint8_t> &cipher_bin) {
  const unsigned char* cipher = cipher_bin.data();

  memcpy(user_pubkey, cipher, USER_PUBKEY_LEN);
  cipher += USER_PUBKEY_LEN;

  memcpy(aes_iv, cipher, AES_IV_LEN);
  cipher += AES_IV_LEN;

  memcpy(gcm_tag, cipher, GCM_TAG_LEN);
  cipher += GCM_TAG_LEN;

  data.clear();
  data.insert(data.end(), cipher, cipher_bin.data() + cipher_bin.size());
}

HybridCipher::HybridCipher(const unsigned char *cipher, size_t len) :
    HybridCipher(vector<uint8_t>(cipher, cipher + len)) {}


vector<uint8_t> HybridCipher::toBytes() {
  vector<uint8_t> tmp_buf;
  tmp_buf.insert(tmp_buf.end(), user_pubkey, user_pubkey + USER_PUBKEY_LEN);
  tmp_buf.insert(tmp_buf.end(), aes_iv, aes_iv + AES_IV_LEN);
  tmp_buf.insert(tmp_buf.end(), gcm_tag, gcm_tag + GCM_TAG_LEN);
  tmp_buf.insert(tmp_buf.end(), data.begin(), data.end());

  return tmp_buf;
}

string HybridCipher::toBase64() {
  vector<uint8_t> bytes = this->toBytes();
  return ext::b64_encode(bytes.data(), bytes.size());
}

string HybridCipher::toString() {
  hexdump("user pubkey", user_pubkey, USER_PUBKEY_LEN);
  hexdump("aes iv", aes_iv, AES_IV_LEN);
  hexdump("gcm tag", gcm_tag, GCM_TAG_LEN);
  hexdump("cipher text", &data[0], data.size());
}