#include "tls_server_threaded.h"
#include "log.h"
#include "pprint.h"

#include "mbedtls/debug.h"
#include <vector>
#include <mbedtls/net_v.h>

using namespace std;

TLSConnectionHandler::TLSConnectionHandler() {
  int ret;

#if defined(MBEDTLS_MEMORY_BUFFER_ALLOC_C)
  unsigned char alloc_buf[100000];
#endif
#if defined(MBEDTLS_SSL_CACHE_C)
  mbedtls_ssl_cache_context cache;
#endif

#if defined(MBEDTLS_MEMORY_BUFFER_ALLOC_C)
  mbedtls_memory_buffer_alloc_init( alloc_buf, sizeof(alloc_buf) );
#endif

#if defined(MBEDTLS_SSL_CACHE_C)
  mbedtls_ssl_cache_init( &cache );
#endif

  mbedtls_x509_crt_init(&srvcert);
  mbedtls_x509_crt_init(&cachain);

  mbedtls_ssl_config_init(&conf);
  mbedtls_ctr_drbg_init(&ctr_drbg);

  mbedtls_entropy_init(&entropy);

  /*
   * 1. Load the certificates and private RSA key
   */
  mbedtls_printf("\n  . Loading the server cert. and key...");
  /*
   * FIXME: This demonstration program uses embedded test certificates.
   * Instead, you may want to use mbedtls_x509_crt_parse_file() to read the
   * server and CA certificates, as well as mbedtls_pk_parse_keyfile().
   */
  ret = mbedtls_x509_crt_parse(&srvcert, (const unsigned char *) mbedtls_test_srv_crt,
                               mbedtls_test_srv_crt_len);
  if (ret != 0) {
    mbedtls_printf(" failed\n  !  mbedtls_x509_crt_parse returned %d\n\n", ret);
    throw std::runtime_error("");
  }

  ret = mbedtls_x509_crt_parse(&cachain, (const unsigned char *) mbedtls_test_cas_pem,
                               mbedtls_test_cas_pem_len);
  if (ret != 0) {
    mbedtls_printf(" failed\n  !  mbedtls_x509_crt_parse returned %d\n\n", ret);
    throw std::runtime_error("");
  }

  mbedtls_pk_init(&pkey);
  ret = mbedtls_pk_parse_key(&pkey, (const unsigned char *) mbedtls_test_srv_key,
                             mbedtls_test_srv_key_len, NULL, 0);
  if (ret != 0) {
    mbedtls_printf(" failed\n  !  mbedtls_pk_parse_key returned %d\n\n", ret);
    throw std::runtime_error("");
  }

  mbedtls_printf(" ok\n");

  /*
   * 1b. Seed the random number generator
   */
  mbedtls_printf("  . Seeding the random number generator...");

  if ((ret = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy,
                                   (const unsigned char *) pers.c_str(),
                                   pers.length())) != 0) {
    mbedtls_printf(" failed: mbedtls_ctr_drbg_seed returned -0x%04x\n",
                   -ret);
    throw std::runtime_error("");
  }

  mbedtls_printf(" ok\n");

  /*
   * 1c. Prepare SSL configuration
   */
  mbedtls_printf("  . Setting up the SSL data....");

  if ((ret = mbedtls_ssl_config_defaults(&conf,
                                         MBEDTLS_SSL_IS_SERVER,
                                         MBEDTLS_SSL_TRANSPORT_STREAM,
                                         MBEDTLS_SSL_PRESET_DEFAULT)) != 0) {
    mbedtls_printf(" failed: mbedtls_ssl_config_defaults returned -0x%04x\n",
                   -ret);
    throw std::runtime_error("");
  }

  mbedtls_ssl_conf_rng(&conf, mbedtls_ctr_drbg_random, &ctr_drbg);

  /*
   * setup debug
   */
  mbedtls_ssl_conf_dbg(&conf, mydebug, NULL);
  // if debug_level is not set (could be set via other constructors), set it to 0
  if (debug_level < 0) {
    debug_level = 0;
  }
  mbedtls_debug_set_threshold(debug_level);

  /* mbedtls_ssl_cache_get() and mbedtls_ssl_cache_set() are thread-safe if
   * MBEDTLS_THREADING_C is set.
   */
#if defined(MBEDTLS_SSL_CACHE_C)
  mbedtls_ssl_conf_session_cache( &conf, &cache,
                                   mbedtls_ssl_cache_get,
                                   mbedtls_ssl_cache_set );
#endif

  mbedtls_ssl_conf_ca_chain(&conf, &cachain, NULL);
  if ((ret = mbedtls_ssl_conf_own_cert(&conf, &srvcert, &pkey)) != 0) {
    mbedtls_printf(" failed\n  ! mbedtls_ssl_conf_own_cert returned %d\n\n", ret);
    throw std::runtime_error("");
  }

  mbedtls_printf(" ok\n");
}

TLSConnectionHandler::~TLSConnectionHandler() {
  mbedtls_x509_crt_free(&srvcert);
  mbedtls_pk_free(&pkey);
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
  mbedtls_net_context *client_fd = &thread_info->client_fd;
  unsigned char buf[1024];
  mbedtls_ssl_context ssl;
  mbedtls_ssl_init(&ssl);

  // thread local data
  mbedtls_ssl_config conf;

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
      LL_DEBUG("  [ #%ld ]  failed: mbedtls_ssl_handshake returned -0x%04x\n",
                     thread_id, -ret);
      goto thread_exit;
    }
  }

  LL_LOG("[socket %d] handshake succeeds", client_fd->fd);

  /*
   * 6. Read the HTTP Request
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
          LL_DEBUG("  [ #%ld ]  connection was closed gracefully\n",
                         thread_id);
          goto thread_exit;

        case MBEDTLS_ERR_NET_CONN_RESET:
          LL_DEBUG("  [ #%ld ]  connection was reset by peer\n",
                         thread_id);
          goto thread_exit;

        default:
          LL_DEBUG("  [ #%ld ]  mbedtls_ssl_read returned -0x%04x\n",
                         thread_id, -ret);
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

thread_exit:
  while ((ret = mbedtls_ssl_close_notify(&ssl)) < 0) {
    if (ret != MBEDTLS_ERR_SSL_WANT_READ &&
        ret != MBEDTLS_ERR_SSL_WANT_WRITE) {
      LL_DEBUG("  [ #%ld ]  failed: mbedtls_ssl_close_notify returned -0x%04x", thread_id, ret);
      goto thread_exit;
    }
  }
  LL_LOG("socket %d closed", client_fd->fd);

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
  /*
  * 7. Write the 200 Response
  */
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
  ret = 0;
}

const string TLSConnectionHandler::pers = "ssl_pthread_server";
sgx_thread_mutex_t TLSConnectionHandler::mutex = SGX_THREAD_MUTEX_INITIALIZER;

void TLSConnectionHandler::mydebug(void *ctx, int level,
                                   const char *file, int line,
                                   const char *str) {
  (void) ctx;
  (void) level;
  long int thread_id = 0;
  sgx_thread_mutex_lock(&mutex);

  mbedtls_printf("%s:%04d: [ #%ld ] %s", file, line, thread_id, str);

  sgx_thread_mutex_unlock(&mutex);
}