#include "tls_server_threaded_t.h"
#include "log.h"
#include "pprint.h"
#include "tls_exch_ca.h"
#include "state.h"

using namespace std;

using namespace exch::enclave::tls;

SSLServer::SSLServer(const TLSCert &cert) {
  int ret;

  // initialize a bunch of context data
  mbedtls_x509_crt_init(&srvcert);
  mbedtls_x509_crt_init(&cachain);
  mbedtls_ssl_config_init(&conf);
  mbedtls_ctr_drbg_init(&ctr_drbg);
  mbedtls_entropy_init(&entropy);

  // Load the certificates and private RSA key
  LL_LOG("Loading the server cert. and key...");

  ret = mbedtls_x509_crt_parse(&srvcert, cert.getCert().data(), cert.getCert().size());
  if (ret != 0) {
    throw runtime_error(utils::mbedtls_error(ret));
  }
  LL_LOG("done loading server cert");

  // length includes the terminating null
  ret = mbedtls_x509_crt_parse(&cachain, (const unsigned char *) exch_dummy_ca, exch_dummy_ca_len);
  if (ret != 0) {
    throw std::runtime_error("mbedtls_x509_crt_parse returned " + to_string(ret));
  }
  LL_DEBUG("done loading CA certs");

  if (0 == mbedtls_pk_can_do(cert.getSkPtr(), MBEDTLS_PK_RSA)) {
    throw runtime_error("RSA key is not provisioned");
  }

  // FIXME: copy the secret key to a local buffer. Ugly but we need this.
  // FIXME: see https://tls.mbed.org/discussions/generic/mbedtls_ssl_conf_own_cert
  auto priv_key_len = mbedtls_pk_get_len(cert.getSkPtr());

  if (priv_key_len != 0) {
    priv_key = (mbedtls_pk_context *) malloc(priv_key_len);
  } else {
    throw runtime_error("cannot get length of private key");
  }

  if (priv_key == nullptr) {
    throw runtime_error("bad alloc");
  }

  memcpy(priv_key, cert.getSkPtr(), priv_key_len);

  if ((ret = mbedtls_ssl_config_defaults(&conf,
                                         MBEDTLS_SSL_IS_SERVER,
                                         MBEDTLS_SSL_TRANSPORT_STREAM,
                                         MBEDTLS_SSL_PRESET_DEFAULT)) != 0) {
    mbedtls_printf(" failed: mbedtls_ssl_config_defaults returned -0x%04x\n", -ret);
    throw std::runtime_error("");
  }

  mbedtls_ssl_conf_rng(&conf, mbedtls_sgx_drbg_random, nullptr);

  // debug
  mbedtls_ssl_conf_dbg(&conf, mydebug, nullptr);
  mbedtls_debug_set_threshold(SSLServer::debug_level);

#if defined(MBEDTLS_SSL_CACHE_C)
  mbedtls_ssl_conf_session_cache( &conf, &cache,
                                   mbedtls_ssl_cache_get,
                                   mbedtls_ssl_cache_set );
#endif

  mbedtls_ssl_conf_ca_chain(&conf, &cachain, nullptr);
  if ((ret = mbedtls_ssl_conf_own_cert(&conf, &srvcert, priv_key)) != 0) {
    mbedtls_printf(" failed\n  ! mbedtls_ssl_conf_own_cert returned %d\n\n", ret);
    throw std::runtime_error("");
  }

  /*
   * make client identity verification mandatory
   * TODO: maybe make it changable?
   */
  mbedtls_ssl_conf_authmode(&conf, MBEDTLS_SSL_VERIFY_REQUIRED);
}

SSLServer::~SSLServer() {
  mbedtls_x509_crt_free(&srvcert);
  mbedtls_pk_free(priv_key);
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

Session SSLServer::establish(long int thread_id, ssl_context *ssl_ctx, bytes &out) {
  int ret, len;
  unsigned char buf[1024];

  mbedtls_ssl_context ssl;
  mbedtls_ssl_init(&ssl);

  mbedtls_net_context *client_fd = &ssl_ctx->client_fd;

  // thread local data
  ssl_ctx->thread_complete = 0;

  LL_LOG("serving socket %d", client_fd->fd);

  Session session {&ssl, ssl_ctx};

  /*
   * 4. Get the SSL context ready
   */
  LL_DEBUG("  [ #%ld ]  Setting up SSL/TLS data", thread_id);
  if ((ret = mbedtls_ssl_setup(&ssl, &conf)) != 0) {
    LL_DEBUG("  [ #%ld ]  failed: mbedtls_ssl_setup returned -0x%04x", thread_id, -ret);
    close(session, true);
  }

  mbedtls_ssl_set_bio(&ssl, client_fd, mbedtls_net_send, mbedtls_sgx_net_recv, nullptr);

  /*
   * 5. Handshake
   */
  LL_DEBUG("  [ #%ld ]  Performing the SSL/TLS handshake", thread_id);

  while ((ret = mbedtls_ssl_handshake(&ssl)) != 0) {
    if (ret != MBEDTLS_ERR_SSL_WANT_READ && ret != MBEDTLS_ERR_SSL_WANT_WRITE) {
      LL_CRITICAL("%s", this->getError(ret).c_str());
      close(session, true);
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
        case 0: LL_DEBUG("EOF reached");
        case MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY: {
          LL_DEBUG("  [ #%ld ]  connection was closed gracefully", thread_id);
          close(session, true);
        }
        case MBEDTLS_ERR_NET_CONN_RESET: {
          LL_DEBUG("  [ #%ld ]  connection was reset by peer", thread_id);
          close(session, false);
        }
        default: {
          LL_DEBUG("  [ #%ld ]  mbedtls_ssl_read returned -0x%04x", thread_id, -ret);
          close(session, false);
        }
      }
      return session;
    }

    len = ret;
    LL_LOG("[socket %d] %d bytes read", client_fd->fd, len);

    out.insert(out.end(), buf, buf + len);

    if (ret > 0)
      break;
  } while (true);

  return session;
}

void SSLServer::close(Session &session, bool notify) {
  int ret;
  if (notify) {
    while ((ret = mbedtls_ssl_close_notify(session.ssl)) < 0) {
      if (ret != MBEDTLS_ERR_SSL_WANT_READ &&
          ret != MBEDTLS_ERR_SSL_WANT_WRITE) {
        LL_DEBUG("Failed: mbedtls_ssl_close_notify returned -0x%04x", ret);
        break;
      }
    }
    LL_LOG("socket closed");
  }

  session.ssl_ctx->thread_complete = 1;

  mbedtls_ssl_free(session.ssl);
  session.ssl = nullptr;
}

int SSLServer::send(Session session, const bytes &data) {
  // write data
  int ret;
  for (size_t written = 0, frags = 0; written < data.size(); written += ret, frags++) {
    while ((ret = mbedtls_ssl_write(session.ssl, data.data() + written, data.size() - written)) <= 0) {
      if (ret != MBEDTLS_ERR_SSL_WANT_READ && ret != MBEDTLS_ERR_SSL_WANT_WRITE) {
        return ret;
      }
    }
  }

  return 0;
}

string SSLServer::getError(int err) {
#ifdef MBEDTLS_ERROR_C
  mbedtls_strerror(err, this->error_msg, sizeof this->error_msg);
  return string(this->error_msg);
#else
  return "";
#endif
}

sgx_thread_mutex_t SSLServer::mutex = SGX_THREAD_MUTEX_INITIALIZER;
int SSLServer::debug_level = 0;

void SSLServer::mydebug(void *ctx, int level,
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