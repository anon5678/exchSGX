//
// Created by fanz on 8/28/17.
//

#ifndef PROJECT_TLS_SERVER_THREADED_H
#define PROJECT_TLS_SERVER_THREADED_H

#include <pthread.h>

#include "../common/ssl_context.h"

typedef struct {
  int active;
  thread_info_t data;
  pthread_t thread;
} pthread_info_t;

#define MAX_NUM_THREADS 5

using namespace std;

int tls_server_init(unsigned int port);

#endif //PROJECT_TLS_SERVER_THREADED_H
