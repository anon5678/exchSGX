#include "tls_server_threaded.h"

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

extern sgx_enclave_id_t eid;

std::atomic<bool> quit(false);
void exitGraceful(int n) {
  (void) n;
  quit.store(true);
}

TLSService::TLSService(const string &hostname,
                       const string &port, TLSService::Role role, size_t n_threads) :
    hostname(hostname), port(port), role(role), ret(0) {
  // initialize the enclave TLS resources
  if (ssl_conn_init(eid, &ret) != SGX_SUCCESS || ret != 0) {
    cerr << "failed to initialize ssl" << endl;
    exit(-1);
  }

  // allocate threads
  threads.resize(n_threads);
  for (auto t : threads) {
    memset(&t, 0, sizeof(pthread_info_t));
  }

  cout << threads.size() << " threads initialized" << endl;
}

TLSService::TLSService(TLSService &&other) noexcept {
  hostname = move(other.hostname);
  port = move(other.port);
  role = other.role;
  ret = 0;

  threads = move(other.threads);

  other.moved_away = true;
}

TLSService::~TLSService() {
  if (!moved_away) {
    ssl_conn_teardown(eid);
  }
}

void TLSService::operator()() {
  // bind to localhost:port
  if ((ret = mbedtls_net_bind(&server_socket,
                              hostname.c_str(), port.c_str(),
                              MBEDTLS_NET_PROTO_TCP)) != 0) {
    cout << " failed! mbedtls_net_bind returned " << ret << endl;
    std::exit(-1);
  }
  cout << "Listening at " << hostname << ": " << port << endl;

  // non-block accept
  std::signal(SIGINT, exitGraceful);
  while (true) {
    // check for Ctrl-C flag
    std::this_thread::sleep_for(std::chrono::seconds(1));
    if (quit.load()) {
      cerr << "Ctrl-C pressed. Quiting..." << endl;
      break;
    }

    // Wait for a client connects
    if (0 != mbedtls_net_set_nonblock(&server_socket)) {
      cerr << "can't set nonblock for the listen socket" << endl;
    }

    ret = mbedtls_net_accept(&server_socket, &client_fd, NULL, 0, NULL);

    if (ret == MBEDTLS_ERR_SSL_WANT_READ) {
      // it means accept would block (i.e. no connection so far)
      // let's don't block and continue!
      ret = 0;
      continue;
    }

    if (ret != 0) {
      fprintf(stderr, "  [ main ] failed: mbedtls_net_accept returned -0x%04x\n", ret);
      break;
    }

    std::cout << "serving " << client_fd.fd << std::endl;

    if ((ret = serve_tls_conn_in_thread(&client_fd)) != 0) {
      fprintf(stderr, "  [ main ]  failed: thread_create returned %d\n", ret);
      mbedtls_net_free(&client_fd);
      continue;
    }

#ifdef MBEDTLS_ERROR_C
    if (ret != 0) {
      char error_buf[100];
      mbedtls_strerror(ret, error_buf, 100);
      mbedtls_printf("  [ main ]  Last error was: -0x%04x - %s\n", -ret, error_buf);
    }
#endif

    ret = 0;
  } // while (true)

  cout << "exiting the loop" << endl;
}

// thread function
void *ecall_handle_tls_conn(void *data) {
  long int thread_id = pthread_self();
  auto *thread_info = (thread_info_t *) data;

  int ret = ssl_conn_handle(eid, thread_id, thread_info);
  if (ret != SGX_SUCCESS) {
    cerr << "failed to make ecall " << ret << endl;
  }

  mbedtls_net_free(&thread_info->client_fd);
  return (NULL);
}

int TLSService::serve_tls_conn_in_thread(const mbedtls_net_context *client_fd) {
  int ret, i;

  for (i = 0; i < threads.size(); i++) {
    if (threads[i].active == 0)
      break;

    if (threads[i].data.thread_complete == 1) {
      mbedtls_printf("  [ main ]  Cleaning up thread %d\n", i);
      pthread_join(threads[i].thread, NULL);
      memset(&threads[i], 0, sizeof(pthread_info_t));
      break;
    }
  }

  if (i == threads.size()) {
    cerr << "all threads in use. try again later" << endl;
    return (-1);
  }

  threads[i].active = 1;
  threads[i].data.config = NULL;
  threads[i].data.thread_complete = 0;
  memcpy(&threads[i].data.client_fd, client_fd, sizeof(mbedtls_net_context));

  if ((ret = pthread_create(&threads[i].thread, NULL, ecall_handle_tls_conn, &threads[i].data)) != 0) {
    return (ret);
  }

  return (0);
}
