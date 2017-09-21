//
// Created by fanz on 7/13/17.
// This file implements the FIFO queue that stores the recent blocks
//

#ifndef PROJECT_LATEST_BLOCKS_H
#define PROJECT_LATEST_BLOCKS_H

#include <queue>

#include "bitcoin/primitives/block.h"
#include "pprint.h"

using namespace std;

// initialized data
enum HeaderSize {
  bitcoin = 80,
};

// XXX: use a constant difficulty for the moment
constexpr unsigned int bitcoinDifficulty = 8;

/*
 * other functions
 */
unsigned int nLeadingZero(const uint256 &hash);

template <unsigned int QUEUE_LENGTH>
class BlockFIFO {
private:
  queue<CBlockHeader> _blocks;

public:
  //! validate a block by checking its hash
  //! \param new_block
  //! \return  true = validated
  bool is_valid_successor(const CBlockHeader &new_block) const {
    if (_blocks.empty())
      return true;

    CBlockHeader prev_block = _blocks.back();

    if (prev_block.GetHash() == new_block.hashPrevBlock &&
        nLeadingZero(new_block.GetHash()) >= bitcoinDifficulty) {
      LL_DEBUG("can push");
      return true;
    }

    LL_LOG("cannot append block %s", new_block.GetHash().ToString().c_str());
    return false;
  }

  bool enqueue(const CBlockHeader &new_header) {
    if (!is_valid_successor(new_header)) {
      return false;
    }

    int nPoped = 0;
    while (_blocks.size() >= QUEUE_LENGTH) {
      _blocks.pop();
      nPoped++;
    }

    if (nPoped > 0)
      LL_LOG("removed %d blocks from FIFO", nPoped);

    _blocks.push(new_header);
    return true;
  }

  uint256 last_block() const { return _blocks.back().GetHash(); }

  size_t size() const { return _blocks.size(); }
};

#endif // PROJECT_LATEST_BLOCKS_H
