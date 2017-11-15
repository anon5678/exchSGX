#include "tls_server_threaded_t.h"
#include "log.h"
#include "pprint.h"
#include "tls_exch_ca.h"
#include "key_rsa_t.h"
#include "utils.h"

#include <vector>
#include <mbedtls/pk.h>
#include "mbedtls/debug.h"
#include "mbedtls/net_v.h"


using namespace std;

TLSConnectionHandler::TLSConnectionHandler() {
  int ret;

  mbedtls_x509_crt_init(&srvcert);
  mbedtls_x509_crt_init(&cachain);

  mbedtls_ssl_config_init(&conf);
  mbedtls_ctr_drbg_init(&ctr_drbg);

  mbedtls_entropy_init(&entropy);
  /*
   * 1. Load the certificates and private RSA key
   */
  LL_LOG("Loading the server cert. and key...");
  if (g_cert_pem.empty()) {
    throw runtime_error("no cert provisioned");
  }

  ret = mbedtls_x509_crt_parse(&srvcert, (unsigned char*) g_cert_pem.data(), g_cert_pem.size());
  if (ret != 0) {
    throw runtime_error(utils::mbedtls_error(ret));
  }
  LL_LOG("done loading server cert");

  // length includes the terminating null
  ret = mbedtls_x509_crt_parse(&cachain, (const unsigned char*) exch_dummy_ca, exch_dummy_ca_len);
  if (ret != 0) {
    throw std::runtime_error("mbedtls_x509_crt_parse returned " + to_string(ret));
  }
  LL_DEBUG("done loading CA certs");

  if (0 == mbedtls_pk_can_do(&g_rsa_sk, MBEDTLS_PK_RSA)){
    throw runtime_error("RSA key is not provisioned");
  }

  mbedtls_pk_context* pkey = &g_rsa_sk;

  if ((ret = mbedtls_ssl_config_defaults(&conf,
                                         MBEDTLS_SSL_IS_SERVER,
                                         MBEDTLS_SSL_TRANSPORT_STREAM,
                                         MBEDTLS_SSL_PRESET_DEFAULT)) != 0) {
    mbedtls_printf(" failed: mbedtls_ssl_config_defaults returned -0x%04x\n", -ret);
    throw std::runtime_error("");
  }

  mbedtls_ssl_conf_rng(&conf, mbedtls_sgx_drbg_random, nullptr);

  /*
   * setup debug
   */
  mbedtls_ssl_conf_dbg(&conf, mydebug, NULL);
  // if debug_level is not set (could be set via other constructors), set it to 0
  mbedtls_debug_set_threshold(TLSConnectionHandler::debug_level);

  /* mbedtls_ssl_cache_get() and mbedtls_ssl_cache_set() are thread-safe if
   * MBEDTLS_THREADING_C is set.
   */
#if defined(MBEDTLS_SSL_CACHE_C)
  mbedtls_ssl_conf_session_cache( &conf, &cache,
                                   mbedtls_ssl_cache_get,
                                   mbedtls_ssl_cache_set );
#endif

  mbedtls_ssl_conf_ca_chain(&conf, &cachain, NULL);
  if ((ret = mbedtls_ssl_conf_own_cert(&conf, &srvcert, pkey)) != 0) {
    mbedtls_printf(" failed\n  ! mbedtls_ssl_conf_own_cert returned %d\n\n", ret);
    throw std::runtime_error("");
  }

  /*
   * make client identity verification mandatory
   * TODO: maybe make it changable?
   */
  mbedtls_ssl_conf_authmode(&conf, MBEDTLS_SSL_VERIFY_REQUIRED);
}

TLSConnectionHandler::~TLSConnectionHandler() {
  mbedtls_x509_crt_free(&srvcert);
  // FIXME
  // mbedtls_pk_free(&pkey);
#if defined(MBEDTLS_SSL_CACHE_C)
  mbedtls_ssl_cache_free( &cache );
#endif
  mbedtls_ctr_drbg_free(&ctr_drbg);
  mbedtls_entropy_free(&entropy);
  mbedtls_ssl_config_free(&conf);

  sgx_thread_mutex_destroy(&mutex);

#if defined(MBEDTLS_MEMORY_BUFFER_ALLOC_C)
  mbedtls_memory_buffer_alloc_free();
#endif

#if defined(_WIN32)
  mbedtls_printf( "  Press Enter to exit this program.\n" );
    fflush( stdout ); getchar();
#endif
}

void TLSConnectionHandler::handle(long int thread_id, thread_info_t *thread_info) {
  int ret, len;
  unsigned char buf[1024];
  mbedtls_ssl_context ssl;
  mbedtls_ssl_config conf;

  mbedtls_ssl_init(&ssl);

  mbedtls_net_context *client_fd = &thread_info->client_fd;

  // thread local data
  memcpy(&conf, &this->conf, sizeof(mbedtls_ssl_config));
  thread_info->config = &conf;
  thread_info->thread_complete = 0;

  vector<uint8_t> data_in;

  LL_LOG("serving socket %d", client_fd->fd);

  /*
   * 4. Get the SSL context ready
   */
  LL_DEBUG("  [ #%ld ]  Setting up SSL/TLS data", thread_id);
  if ((ret = mbedtls_ssl_setup(&ssl, thread_info->config)) != 0) {
    LL_DEBUG("  [ #%ld ]  failed: mbedtls_ssl_setup returned -0x%04x",
                   thread_id, -ret);
    goto thread_exit;
  }

  mbedtls_ssl_set_bio(&ssl, client_fd, mbedtls_net_send, mbedtls_sgx_net_recv, nullptr);

  /*
   * 5. Handshake
   */
  LL_DEBUG("  [ #%ld ]  Performing the SSL/TLS handshake", thread_id);

  while ((ret = mbedtls_ssl_handshake(&ssl)) != 0) {
    if (ret != MBEDTLS_ERR_SSL_WANT_READ && ret != MBEDTLS_ERR_SSL_WANT_WRITE) {
      LL_CRITICAL("%s", this->getError(ret).c_str());
      goto thread_exit;
    }
  }

  LL_LOG("[socket %d] handshake succeeds", client_fd->fd);

  /*
   * 6. Read from the client
   */
  LL_DEBUG("  [ #%ld ]  < Read from client", thread_id);


  do {
    len = sizeof(buf) - 1;
    memset(buf, 0, sizeof(buf));
    ret = mbedtls_ssl_read(&ssl, buf, len);

    // handle potential errors
    if (ret == MBEDTLS_ERR_SSL_WANT_READ || ret == MBEDTLS_ERR_SSL_WANT_WRITE)
      continue;

    if (ret <= 0) {
      switch (ret) {
        case 0:
          LL_DEBUG("EOF reached");
          goto thread_exit;
        case MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY:
          LL_DEBUG("  [ #%ld ]  connection was closed gracefully", thread_id);
          goto thread_exit;

        case MBEDTLS_ERR_NET_CONN_RESET:
          LL_DEBUG("  [ #%ld ]  connection was reset by peer", thread_id);
          goto exit_without_notify;

        default:
          LL_DEBUG("  [ #%ld ]  mbedtls_ssl_read returned -0x%04x", thread_id, -ret);
          goto thread_exit;
      }
    }

    len = ret;
    LL_LOG("[socket %d] %d bytes read", client_fd->fd, len);

    // insert the actual data
    data_in.insert(data_in.end(), buf, buf + len);

    if (ret > 0)
      break;
  } while (true);

  hexdump("data from client", data_in.data(), data_in.size());

  // write dummy back
  {
    vector<uint8_t> back {4, 3, 2, 1};

    size_t written = 0, frags = 0;
    for( written = 0, frags = 0; written < back.size(); written += ret, frags++ )
    {
      while( ( ret = mbedtls_ssl_write( &ssl, back.data() + written, back.size() - written ) ) <= 0 )
      {
        if( ret == MBEDTLS_ERR_NET_CONN_RESET )
        {
          LL_CRITICAL("failed! peer closed the connection" );
          goto exit_without_notify;
        }

        if( ret != MBEDTLS_ERR_SSL_WANT_READ &&
            ret != MBEDTLS_ERR_SSL_WANT_WRITE )
        {
          mbedtls_printf( "failed! mbedtls_ssl_write returned %d", ret );
          goto exit_without_notify;
        }
      }
    }
    hexdump("written to client: ", data_in.data(), data_in.size());
  }

thread_exit:
  while ((ret = mbedtls_ssl_close_notify(&ssl)) < 0) {
    if (ret != MBEDTLS_ERR_SSL_WANT_READ &&
        ret != MBEDTLS_ERR_SSL_WANT_WRITE) {
      LL_DEBUG("  [ #%ld ]  failed: mbedtls_ssl_close_notify returned -0x%04x", thread_id, ret);
      break;
    }
  }
  LL_LOG("socket %d closed", client_fd->fd);

exit_without_notify:

#ifdef MBEDTLS_ERROR_C
  if (ret != 0) {
    char error_buf[100];
    mbedtls_strerror(ret, error_buf, 100);
    LL_CRITICAL("  [ #%ld ]  Last error was: -0x%04x - %s", thread_id, -ret, error_buf);
  }
#endif

  mbedtls_ssl_free(&ssl);
  // do not free config, as it's allocated outside of the enclave
  // mbedtls_ssl_config_free(&conf);

  thread_info->config = nullptr;
  thread_info->thread_complete = 1;
}

int send(long thread_id, mbedtls_ssl_context* ssl, const vector<uint8_t> &data) {
#if 0
  LL_DEBUG("  [ #%ld ]  > Write to client", thread_id);

  int len;
  int ret;

  while ((ret = mbedtls_ssl_write(ssl, data.data(), len)) <= 0) {
    if (ret == MBEDTLS_ERR_NET_CONN_RESET) {
      LL_DEBUG("  [ #%ld ]  failed: peer closed the connection", thread_id);
      return ret;
    }

    if (ret != MBEDTLS_ERR_SSL_WANT_READ && ret != MBEDTLS_ERR_SSL_WANT_WRITE) {
      LL_DEBUG("  [ #%ld ]  failed: mbedtls_ssl_write returned -0x%04x", thread_id, ret);
      return ret;
    }
  }

  len = ret;
  LL_DEBUG("  [ #%ld ]  %d bytes written", thread_id, len);
#endif

  return 0;
}

string TLSConnectionHandler::getError(int errno) {
#ifdef MBEDTLS_ERROR_C
  mbedtls_strerror(errno, this->error_msg, sizeof this->error_msg);
  return string(this->error_msg);
#else
  return "";
#endif
}

const string TLSConnectionHandler::pers = "ssl_pthread_server";
sgx_thread_mutex_t TLSConnectionHandler::mutex = SGX_THREAD_MUTEX_INITIALIZER;
int TLSConnectionHandler::debug_level = 0;

void TLSConnectionHandler::mydebug(void *ctx, int level,
                                   const char *file, int line,
                                   const char *str) {
  (void) ctx;
  (void) level;
  if (level > debug_level) return;
  long int thread_id = 0;

  sgx_thread_mutex_lock(&mutex);
  mbedtls_printf("%s:%04d: [ #%ld ] %s", file, line, thread_id, str);
  sgx_thread_mutex_unlock(&mutex);
}