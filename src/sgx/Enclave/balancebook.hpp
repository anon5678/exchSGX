//
// Created by fanz on 9/21/17.
//

#ifndef PROJECT_BALANCE_BOOK_H
#define PROJECT_BALANCE_BOOK_H

#include <map>
#include <string>

class BalanceBook {
 private:
  map<string, int> book;
 public:
  BalanceBook() = default;

  void deposit(string user_id, int amount) {
    book[user_id] = amount;
  }
};

#endif //PROJECT_BALANCE_BOOK_H
