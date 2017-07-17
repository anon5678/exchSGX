//
// Created by fanz on 7/13/17.
// This file implements the FIFO queue that stores the recent blocks
//

#ifndef PROJECT_LATEST_BLOCKS_H
#define PROJECT_LATEST_BLOCKS_H

#include <queue>
#include "bitcoin/primitives/block.h"

using namespace std;

inline int nZero(uint256 hash) {
  string h = hash.GetHex();
  int i = 0;
  while (h[i] == '0' && i < h.length()) {
    i++;
  }
  LL_DEBUG("%s => %d", hash.GetHex().c_str(), i);
  return i;
}

template<unsigned int WINDOW>
class LatestBlocks {
 private:
  queue<CBlockHeader> headers;

 public:
  //! validate a block by checking its hash
  //! \param new_block
  //! \return  true = validated
  bool IsAppendable(const CBlockHeader &new_block) const {
    if (headers.empty())
      return true;

    CBlockHeader prev_block = headers.back();

    if (prev_block.GetHash() == new_block.hashPrevBlock
        && nZero(new_block.GetHash()) >= 8) {
      LL_DEBUG("can push");
      return true;
    }

    LL_CRITICAL("cannot append block %s", new_block.GetHash().ToString().c_str());
    return false;
  }

  bool AppendBlock(const CBlockHeader &new_header) {
    if (!IsAppendable(new_header)) {
      return false;
    }

    int nPoped = 0;
    while (headers.size() >= WINDOW) {
      headers.pop();
      nPoped++;
    }

    if (nPoped > 0)
        LL_NOTICE("removed %d blocks from FIFO", nPoped);

    headers.push(new_header);
    return true;
  }

  size_t size() const {
    return headers.size();
  }
};

#endif //PROJECT_LATEST_BLOCKS_H
