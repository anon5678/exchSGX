//
// Created by fanz on 7/13/17.
// This file implements the FIFO queue that stores the recent blocks
//

#ifndef PROJECT_LATEST_BLOCKS_H
#define PROJECT_LATEST_BLOCKS_H

#include <queue>
#include "bitcoin/primitives/block.h"

using namespace std;

template<unsigned int WINDOW>
class LatestBlocks {
 public:
  bool pushable() {
    // TODO: validate the blockchain
    return true;
  }

  void push(const CBlockHeader& new_header) {
    while (headers.size() >= WINDOW) {
      headers.pop();
    }

    headers.push(new_header);
  }

 private:
  queue<CBlockHeader> headers;
};

#endif //PROJECT_LATEST_BLOCKS_H
