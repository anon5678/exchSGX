#include "tls_client.h"
#include "log.h"

#if !defined(MBEDTLS_CONFIG_FILE)
#include "mbedtls/config.h"
#else
#include MBEDTLS_CONFIG_FILE
#endif

#include "mbedtls/platform.h"
#include "mbedtls/net_v.h"
#include "mbedtls/net_f.h"
#include "mbedtls/ssl.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/certs.h"
#include "mbedtls/x509.h"
#include "mbedtls/error.h"
#include "mbedtls/debug.h"
#include "pprint.h"

#include <stdlib.h>
#include <string.h>
#include <exception>
#include <vector>

using namespace std;

static void my_debug(void *ctx, int level,
                     const char *file, int line,
                     const char *str) {
  const char *p, *basename;
  (void) (ctx);

  /* Extract basename from file */
  for (p = basename = file; *p != '\0'; p++)
    if (*p == '/' || *p == '\\')
      basename = p + 1;

  mbedtls_printf("%s:%04d: |%d| %s", basename, line, level, str);
}

#if defined(MBEDTLS_X509_CRT_PARSE_C)
/*
 * Enabled if debug_level > 1 in code below
 */
static int my_verify(void *data, mbedtls_x509_crt *crt, int depth, uint32_t *flags) {
  char buf[1024];
  ((void) data);

  LL_DEBUG("\nVerify requested for (Depth %d):", depth);
  mbedtls_x509_crt_info(buf, sizeof(buf) - 1, "", crt);
  LL_DEBUG("%s", buf);

  if ((*flags) == 0) {
    LL_DEBUG("  This certificate has no flags");
  } else {
    mbedtls_x509_crt_verify_info(buf, sizeof(buf), "  ! ", *flags);
    LL_DEBUG("%s", buf);
  }

  return (0);
}
#endif /* MBEDTLS_X509_CRT_PARSE_C */

TLSClient::TLSClient(const string hostname, unsigned int port)
    : hostname(hostname), port(port), isConnected(false) {
  // init the return code
  ret = 0;
  
  // allocate and initialize resources
  mbedtls_net_init(&server_fd);
  mbedtls_ssl_init(&ssl);
  mbedtls_ssl_config_init(&conf);
  memset(&saved_session, 0, sizeof(mbedtls_ssl_session));
  mbedtls_ctr_drbg_init(&ctr_drbg);
#if defined(MBEDTLS_X509_CRT_PARSE_C)
  mbedtls_x509_crt_init(&cacert);
  mbedtls_x509_crt_init(&clicert);
  mbedtls_pk_init(&pkey);
#endif
  LL_DEBUG("resources allocated and initialized");

  // set debug level
#if defined(MBEDTLS_DEBUG_C)
  mbedtls_debug_set_threshold(0);
#endif

  mbedtls_entropy_init(&entropy);
  LL_DEBUG("entropy initialized");

  /*
   * 0. Initialize the RNG and the session data
   */
  if ((ret = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy,
                                   (const unsigned char *) pers,
                                   strlen(pers))) != 0) {
    LL_CRITICAL(" mbedtls_ctr_drbg_seed returned -%#x", -ret);
    throw std::runtime_error("mbedtls_ctr_drbg_seed failed");
  }

  /*
   * 1. Load the trusted CA
   */
#if defined(MBEDTLS_X509_CRT_PARSE_C)
  ret = mbedtls_x509_crt_parse(&cacert,
                               (const unsigned char *) mbedtls_test_cas_pem,
                               mbedtls_test_cas_pem_len);
  if (ret < 0) {
    throw std::runtime_error("mbedtls_x509_crt_parse failed");
  }

#endif /* MBEDTLS_X509_CRT_PARSE_C */
}

void TLSClient::Connect() {
  if (isConnected) {
    LL_WARNING("trying to already connected");
    return;
  }

  // init data
  ret = 0;

  // connect
  LL_DEBUG("connecting over TCP: %s:%d...", hostname.c_str(), port);

  if ((ret = mbedtls_net_connect(&server_fd,
                                 hostname.c_str(),
                                 to_string(port).c_str(),
                                 MBEDTLS_NET_PROTO_TCP)) != 0) {
    throw std::runtime_error("can't connect to " + hostname + to_string(port) + ". Is the server running?");
  }

  ret = mbedtls_net_set_block(&server_fd);
  if (ret != 0) {
    throw std::runtime_error("net_set_(non)block returned " + to_string(ret));
  }

  // setup tls context
  LL_DEBUG("Setting up the SSL/TLS structure...");

  if ((ret = mbedtls_ssl_config_defaults(&conf,
                                         MBEDTLS_SSL_IS_CLIENT,
                                         MBEDTLS_SSL_TRANSPORT_STREAM,
                                         MBEDTLS_SSL_PRESET_DEFAULT)) != 0) {
    throw runtime_error("mbedtls_ssl_config_defaults");
  }

  mbedtls_ssl_conf_verify(&conf, my_verify, NULL);

#if defined(MBEDTLS_SSL_MAX_FRAGMENT_LENGTH)
  if ((ret = mbedtls_ssl_conf_max_frag_len(&conf, MBEDTLS_SSL_MAX_FRAG_LEN_NONE)) != 0) {
    throw runtime_error("mbedtls_ssl_conf_max_frag_len");
  }
#endif

  mbedtls_ssl_conf_rng(&conf, mbedtls_ctr_drbg_random, &ctr_drbg);
  mbedtls_ssl_conf_dbg(&conf, my_debug, NULL);
  mbedtls_ssl_conf_read_timeout(&conf, 0);
  mbedtls_ssl_conf_ca_chain(&conf, &cacert, NULL);

#if defined(MBEDTLS_SSL_SESSION_TICKETS)
  mbedtls_ssl_conf_session_tickets(&conf, MBEDTLS_SSL_SESSION_TICKETS_ENABLED);
#endif

#if defined(MBEDTLS_SSL_RENEGOTIATION)
  mbedtls_ssl_conf_renegotiation(&conf, MBEDTLS_SSL_RENEGOTIATION_DISABLED);
#endif

  if ((ret = mbedtls_ssl_setup(&ssl, &conf)) != 0) {
    throw runtime_error("mbedtls_ssl_setup");
  }

#if defined(MBEDTLS_X509_CRT_PARSE_C)
  if ((ret = mbedtls_ssl_set_hostname(&ssl, hostname.c_str())) != 0) {
    throw runtime_error("mbedtls_ssl_set_hostname");
  }
#endif

  mbedtls_ssl_set_bio(&ssl, &server_fd, mbedtls_net_send, mbedtls_net_recv, mbedtls_net_recv_timeout);

  // tls handshake
  LL_DEBUG("Performing the SSL/TLS handshake");

  while ((ret = mbedtls_ssl_handshake(&ssl)) != 0) {
    if (ret != MBEDTLS_ERR_SSL_WANT_READ && ret != MBEDTLS_ERR_SSL_WANT_WRITE) {

#if defined(MBEDTLS_X509_CRT_PARSE_C)
      LL_DEBUG("Verifying peer X.509 certificate...");
      if ((flags = mbedtls_ssl_get_verify_result(&ssl)) != 0) {
        LL_CRITICAL("X.509 certificate failed to verify");
        char temp_buf[1024];
        if (mbedtls_ssl_get_peer_cert(&ssl) != nullptr) {
          LL_CRITICAL("Peer certificate information");
          mbedtls_x509_crt_info((char *) temp_buf, sizeof(temp_buf) - 1, "|-", mbedtls_ssl_get_peer_cert(&ssl));
          mbedtls_printf("%s\n", temp_buf);
        } else {
          LL_CRITICAL("peers has no certificate");
        }
      } else {
        LL_DEBUG("X.509 Verifies");
      }
#endif /* MBEDTLS_X509_CRT_PARSE_C */
      if (ret == MBEDTLS_ERR_X509_CERT_VERIFY_FAILED) {
        LL_CRITICAL("Unable to verify the server's certificate.");
      }
      throw runtime_error("mbedtls_ssl_handshake failed with errno " + to_string(ret));
    }
  }

  LL_NOTICE("session connected: [%s, %s]",
            mbedtls_ssl_get_version(&ssl), mbedtls_ssl_get_ciphersuite(&ssl));

  if ((ret = mbedtls_ssl_get_record_expansion(&ssl)) >= 0) {
    LL_DEBUG("Record expansion is [%d]", ret);
  } else
    LL_DEBUG("Record expansion is [unknown (compression)]");

#if defined(MBEDTLS_SSL_MAX_FRAGMENT_LENGTH)
  LL_DEBUG("Maximum fragment length is [%u]",
           (unsigned int) mbedtls_ssl_get_max_frag_len(&ssl));
#endif

  isConnected = true;
}

void TLSClient::Send(const vector<uint8_t> &data) {
  if (!isConnected) {
    throw runtime_error("not connected yet");
  }

  // write data
  for (int written = 0, frags = 0; written < data.size(); written += ret, frags++) {
    while ((ret = mbedtls_ssl_write(&ssl, data.data() + written, data.size() - written)) <= 0) {
      if (ret != MBEDTLS_ERR_SSL_WANT_READ &&
          ret != MBEDTLS_ERR_SSL_WANT_WRITE) {
        throw runtime_error("mbedtls_ssl_write returned" + to_string(ret));
      }
    }
  }
  hexdump("bytes sent", data.data(), data.size());
}


void TLSClient::SendWaitRecv(const vector<uint8_t> &data_in, vector<uint8_t> &data_out) {
  if (!isConnected) {
    throw runtime_error("not connected yet");
  }

  // write data
  for (int written = 0, frags = 0; written < data_in.size(); written += ret, frags++) {
    while ((ret = mbedtls_ssl_write(&ssl, data_in.data() + written, data_in.size() - written)) <= 0) {
      if (ret != MBEDTLS_ERR_SSL_WANT_READ &&
          ret != MBEDTLS_ERR_SSL_WANT_WRITE) {
        throw runtime_error("mbedtls_ssl_write returned" + to_string(ret));
      }
    }
  }

  unsigned char buf[4096];
  /*
    mbedtls_ssl_read returns the number of bytes read, or 0 for EOF, or
    MBEDTLS_ERR_SSL_WANT_READ or MBEDTLS_ERR_SSL_WANT_WRITE, or
    MBEDTLS_ERR_SSL_CLIENT_RECONNECT (see below), or another negative
    error code.
  */

  int n_data;
  while (true) {
    n_data = mbedtls_ssl_read(&ssl, buf, sizeof(buf));

    // handle possible errors
    if (n_data == MBEDTLS_ERR_SSL_WANT_READ ||
        n_data == MBEDTLS_ERR_SSL_WANT_WRITE)
      continue;

    if (n_data < 0) {
      ret = n_data;
      switch (n_data) {
        case MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY:
          LL_CRITICAL(" connection was closed gracefully");
          throw runtime_error("connection was closed gracefully");
        case MBEDTLS_ERR_NET_CONN_RESET:
          LL_CRITICAL(" connection was reset by peer");
          throw runtime_error("connected reset");
        default:
          LL_CRITICAL(" mbedtls_ssl_read returned 0x%x", n_data);
          throw runtime_error("mbedtls_ssl_read returned non-sense");
      }
    }

    // EOF reached
    if (n_data == 0) {
      LL_DEBUG("eof reached");
      break;
    }

    // otherwise store the bytes read
    data_out.insert(data_out.end(), buf, buf + n_data);
  }
}

void TLSClient::Close() {
  do ret = mbedtls_ssl_close_notify(&ssl);
  while (ret == MBEDTLS_ERR_SSL_WANT_WRITE);
  ret = 0;

  LL_DEBUG("closed %s:%d", hostname.c_str(), port);
}

string TLSClient::GetError() {
#ifdef MBEDTLS_ERROR_C
  if (ret != 0) {
    char error_buf[100];
    mbedtls_strerror(ret, error_buf, sizeof error_buf);
    return string(error_buf);
  }
#endif
  return "";
}

TLSClient::~TLSClient() {
  mbedtls_net_free(&server_fd);
#if defined(MBEDTLS_X509_CRT_PARSE_C)
  mbedtls_x509_crt_free(&clicert);
  mbedtls_x509_crt_free(&cacert);
  mbedtls_pk_free(&pkey);
#endif
  mbedtls_ssl_session_free(&saved_session);
  mbedtls_ssl_free(&ssl);
  mbedtls_ssl_config_free(&conf);
  mbedtls_ctr_drbg_free(&ctr_drbg);
  mbedtls_entropy_free(&entropy);
}

const char *TLSClient::pers = "ssl_pthread_server";
