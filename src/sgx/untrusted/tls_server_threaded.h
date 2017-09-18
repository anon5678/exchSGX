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

class TLSService {
 public:
  enum Role {
    FAIRNESS_SERVER,
    END_USER_SERVICE,
  };

  TLSService(const TLSService &) = delete;
  TLSService &operator=(const TLSService &) = delete;

  TLSService(TLSService &&) noexcept;
  TLSService &operator=(TLSService &&) = delete;

  TLSService(const string &hostname, const string &port, TLSService::Role role, size_t n_threads);
  ~TLSService();
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
