#ifndef PROJECT_BALANCE_BOOK_H
#define PROJECT_BALANCE_BOOK_H

#include <map>
#include <string>
#include <stdexcept>
#include "log.h"

using namespace std;

class BalanceBook {
 private:
  map<string, int> book;
 public:
  BalanceBook() = default;

  void deposit(string user_id, int amount) {
    try {

      book[user_id] = amount;
    }
    catch (const std::exception &e) {
      LL_CRITICAL("%s", e.what());
    }
  }
};

#endif //PROJECT_BALANCE_BOOK_H
