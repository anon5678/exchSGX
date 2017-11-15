#include "tls_server_threaded_u.h"

#include <cstdio>
#define mbedtls_fprintf    fprintf
#define mbedtls_printf     printf
#define mbedtls_snprintf   snprintf

#include <cstdlib>
#include <cstring>
#include <pthread.h>
#include <iostream>
#include <atomic>
#include <csignal>
#include <thread>

#include "mbedtls/ssl.h"
#include "mbedtls/net_v.h"
#include "mbedtls/net_f.h"
#include "mbedtls/error.h"
#include "Enclave_u.h"
#include "interrupt.h"
#include "../common/ssl_context.h"

extern sgx_enclave_id_t eid;

#include <log4cxx/logger.h>
#include <log4cxx/propertyconfigurator.h>
#include <mbedtls/net_v.h>

namespace exch{
namespace tls {
log4cxx::LoggerPtr logger(log4cxx::Logger::getLogger("tls_server_threaded_u.cpp"));
}
}

using exch::tls::logger;

TLSServerThreadPool::TLSServerThreadPool(const string &hostname, const string &port,
                       TLSServerThreadPool::Role role, size_t n_threads) :
    hostname(hostname), port(port), role(role), ret(0) {
  // initialize the enclave TLS resources
  if (ssl_conn_init(eid, &ret) != SGX_SUCCESS || ret != 0) {
    LOG4CXX_ERROR(logger, "failed to init TLSService");
    exit(-1);
  }

  // allocate threads
  threads.resize(n_threads);
  for (auto t : threads) {
    memset(&t, 0, sizeof(pthread_info_t));
  }

  LOG4CXX_INFO(logger, "" << threads.size() << " threads initialized");
}

TLSServerThreadPool::TLSServerThreadPool(TLSServerThreadPool &&other) noexcept {
  hostname = move(other.hostname);
  port = move(other.port);
  role = other.role;
  ret = 0;

  threads = move(other.threads);

  other.moved_away = true;
}

TLSServerThreadPool::~TLSServerThreadPool() {
  if (!moved_away) {
    ssl_conn_teardown(eid);
  }
}

void TLSServerThreadPool::operator()() {
  // bind to localhost:port
  if ((ret = mbedtls_net_bind(&server_socket,
                              hostname.c_str(), port.c_str(),
                              MBEDTLS_NET_PROTO_TCP)) != 0) {
    LOG4CXX_ERROR(logger, "failed! mbedtls_net_bind returns " << ret);
    std::exit(-1);
  }
  LOG4CXX_INFO(logger, "TLSService listening at " << hostname << ":" << port);

  while (!exch::interrupt::quit.load()) {
    this_thread::sleep_for(chrono::seconds(1));

    // Wait for a client connects
    if (0 != mbedtls_net_set_nonblock(&server_socket)) {
      LOG4CXX_ERROR(logger, "can't set nonblock for the listen socket")
    }

    ret = mbedtls_net_accept(&server_socket, &client_fd, nullptr, 0, nullptr);

    if (ret == MBEDTLS_ERR_SSL_WANT_READ) {
      // it means accept would block (i.e. no connection so far)
      // let's don't block and continue!
      ret = 0;
      continue;
    }

    if (ret != 0) {
      LOG4CXX_ERROR(logger, "mbedtls_net_accept returns " << ret);
      break;
    }

    LOG4CXX_INFO(logger, "connected at socket %d" << client_fd.fd);

    if ((ret = serve_tls_conn_in_thread(&client_fd)) != 0) {
      LOG4CXX_ERROR(logger, "failed to create threads: " << ret);
      mbedtls_net_free(&client_fd);
      continue;
    }

#ifdef MBEDTLS_ERROR_C
    if (ret != 0) {
      char error_buf[100];
      mbedtls_strerror(ret, error_buf, 100);
      LOG4CXX_ERROR(logger, "last error was: " << error_buf);
    }
#endif

    ret = 0;
  } // while (true)

  LOG4CXX_INFO(logger, "shutting down the TLS server...");
}

// thread function
void *ecall_handle_tls_conn(void *data) {
  long int thread_id = pthread_self();
  auto *thread_info = (thread_info_t *) data;

  int ret = ssl_conn_handle(eid, thread_id, thread_info);
  if (ret != SGX_SUCCESS) {
    LOG4CXX_ERROR(logger, "failed to make ecall");
  }

  // cleanup the thread if finished
  if (thread_info->thread_complete == 1) {
    LOG4CXX_INFO(logger, "cleaning up socket " << thread_info->client_fd.fd);
    mbedtls_net_free(&thread_info->client_fd);
  }
  return nullptr;
}

int TLSServerThreadPool::serve_tls_conn_in_thread(const mbedtls_net_context *client_fd) {
  int ret, i;

  for (i = 0; i < threads.size(); i++) {
    if (threads[i].active == 0)
      break;

    if (threads[i].data.thread_complete == 1) {
      pthread_join(threads[i].thread, nullptr);
      memset(&threads[i], 0, sizeof(pthread_info_t));
      break;
    }
  }

  if (i == threads.size()) {
    LOG4CXX_ERROR(logger, "all threads are in use. try again later.")
    return (-1);
  }

  threads[i].active = 1;
  threads[i].data.config = nullptr;
  threads[i].data.thread_complete = 0;
  memcpy(&threads[i].data.client_fd, client_fd, sizeof(mbedtls_net_context));

  if ((ret = pthread_create(&threads[i].thread, nullptr, ecall_handle_tls_conn, &threads[i].data)) != 0) {
    return (ret);
  }

  return (0);
}
