#ifndef PROJECT_TLS_SERVER_THREADED_H
#define PROJECT_TLS_SERVER_THREADED_H

#include <pthread.h>
#include <vector>
#include <string>

#include "../common/ssl_context.h"

typedef struct {
  int active;
  thread_info_t data;
  pthread_t thread;
} pthread_info_t;

#define MAX_NUM_THREADS 5

using namespace std;

class TLSServerThreadPool {
 public:
  enum Role {
    FAIRNESS_SERVER,
    END_USER_SERVICE,
  };

  TLSServerThreadPool(const TLSServerThreadPool &) = delete;
  TLSServerThreadPool &operator=(const TLSServerThreadPool &) = delete;

  TLSServerThreadPool(TLSServerThreadPool &&) noexcept;
  TLSServerThreadPool &operator=(TLSServerThreadPool &&) = delete;

  TLSServerThreadPool(const string &hostname, const string &port, TLSServerThreadPool::Role role, size_t n_threads);
  ~TLSServerThreadPool();
  void operator()();

 private:
  string hostname;
  string port;
  Role role;
  int ret;

  // set in the move constructor
  bool moved_away = false;

  // resources
  mbedtls_net_context server_socket, client_fd;
  vector<pthread_info_t> threads;

  int serve_tls_conn_in_thread(const mbedtls_net_context *client_fd);
};

#endif //PROJECT_TLS_SERVER_THREADED_H
