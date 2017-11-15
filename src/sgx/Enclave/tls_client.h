#include <stdio.h>
#include <stdlib.h>

#include "Enclave_t.h"
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

#ifndef TLS_CLIENT_H
#define TLS_CLIENT_H

#include <string>
#include <vector>

using namespace std;

class TLSClient {
 private:
  // error number
  int ret;
  const string hostname;
  const unsigned int port;

  static const char *pers;

  // predefined set of allowed peers.
  // Names are used for cert verification.
  const string allowed_peers[5] =
  {
      "exch-enclave-1",
      "exch-enclave-2",
      "exch-enclave-3",
      "exch-enclave-4",
      "exch-enclave-5",
  };

  // resources
  mbedtls_net_context server_fd;
  mbedtls_entropy_context entropy;
  mbedtls_ctr_drbg_context ctr_drbg;
  mbedtls_ssl_context ssl;
  mbedtls_ssl_config conf;
  mbedtls_ssl_session saved_session;
#if defined(MBEDTLS_X509_CRT_PARSE_C)
  uint32_t flags;
  mbedtls_x509_crt cacert;
  mbedtls_x509_crt clicert;
  mbedtls_pk_context* pkey;
#endif

 private:
  bool isConnected;


 public:
  TLSClient(string hostname, unsigned int port);
  ~TLSClient();

  string GetError();
  void Connect() throw(runtime_error);
  void Send(const vector<uint8_t>& data);
  int SendWaitRecv(const vector<uint8_t> &data_in, vector<uint8_t> &data_out) throw (runtime_error);
  void Close();
};

#endif
