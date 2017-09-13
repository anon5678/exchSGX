#include <stdio.h>
#define mbedtls_fprintf    fprintf
#define mbedtls_printf     printf
#define mbedtls_snprintf   snprintf

#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <iostream>
#include <atomic>
#include <csignal>

#include "mbedtls/ssl.h"
#include "mbedtls/net_v.h"
#include "mbedtls/net_f.h"
#include "mbedtls/error.h"
#include "Enclave_u.h"
#include "Utils.h"

#include <sgx_urts.h>
#include <thread>
#include <mbedtls/net_v.h>

#include "tls_server_threaded.h"

extern sgx_enclave_id_t eid;

static pthread_info_t threads[MAX_NUM_THREADS];

// thread function
void *ecall_handle_tls_conn(void *data);
static int serve_tls_conn_in_thread(mbedtls_net_context *client_fd);
mbedtls_net_context listen_fd, client_fd;

std::atomic<bool> quit(false);
void exitGraceful(int n) { (void)n; quit.store(true); }

int tls_server_init(unsigned int port) {
  std::signal(SIGINT, exitGraceful);
  int ret = 0;

  // initialize
  if (ssl_conn_init(eid) != SGX_SUCCESS) {
    cerr << "failed to initialize ssl" << endl;
    exit(-1);
  }

  // initialize threads
  memset(threads, 0, sizeof(threads));

  // bind
  if ((ret = mbedtls_net_bind(&listen_fd, nullptr,
                              to_string(port).c_str(),
                              MBEDTLS_NET_PROTO_TCP)) != 0) {
    cout << " failed! mbedtls_net_bind returned " << ret << endl;
    std::exit(-1);
  }
  cout << "Listening at localhost: " << port << endl;

  // non-block accept
  while (true) {
    // check for Ctrl-C flag
    std::this_thread::sleep_for (std::chrono::seconds(1));
    if (quit.load()) {
      cerr << "Ctrl-C pressed. Quiting..." << endl;
      break;
    }

    /*
     * 3. Wait until a client connects
     */
    if (0 != mbedtls_net_set_nonblock(&listen_fd)) {
      cerr << "can't set nonblock for the listen socket" << endl;
    }

    ret = mbedtls_net_accept(&listen_fd, &client_fd, NULL, 0, NULL);

    if (ret == MBEDTLS_ERR_SSL_WANT_READ) {
      // it means accept would block
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

  sgx_destroy_enclave(eid);
  return (ret);
}

// thread function
void *ecall_handle_tls_conn(void *data) {
  long int thread_id = pthread_self();
  thread_info_t *thread_info = (thread_info_t *) data;

  int ret = ssl_conn_handle(eid, thread_id, thread_info);
  if (ret != SGX_SUCCESS) {
    cerr << "failed to make ecall " << ret << endl;
  }

  mbedtls_net_free(&thread_info->client_fd);
  return (NULL);
}

static int serve_tls_conn_in_thread(mbedtls_net_context *client_fd) {
  int ret, i;

  for (i = 0; i < MAX_NUM_THREADS; i++) {
    if (threads[i].active == 0)
      break;

    if (threads[i].data.thread_complete == 1) {
      mbedtls_printf("  [ main ]  Cleaning up thread %d\n", i);
      pthread_join(threads[i].thread, NULL);
      memset(&threads[i], 0, sizeof(pthread_info_t));
      break;
    }
  }

  if (i == MAX_NUM_THREADS)
    return (-1);

  threads[i].active = 1;
  threads[i].data.config = NULL;
  threads[i].data.thread_complete = 0;
  memcpy(&threads[i].data.client_fd, client_fd, sizeof(mbedtls_net_context));

  if ((ret = pthread_create(&threads[i].thread, NULL, ecall_handle_tls_conn, &threads[i].data)) != 0) {
    return (ret);
  }

  return (0);
}