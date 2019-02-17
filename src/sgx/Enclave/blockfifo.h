#ifndef TESSERACT_BLOCKFIFO_H
#define TESSERACT_BLOCKFIFO_H

#include <deque>

#include "bitcoin/primitives/block.h"
#include "../common/errno.h"
#include "pprint.h"

using namespace std;

// initialized data
enum HeaderSize {
  bitcoin = 80,
};

/*
 * other functions
 */
unsigned int nLeadingZero(const uint256 &hash);

template<unsigned int QUEUE_LENGTH>
class BlockFIFO {
 private:
  deque<CBlockHeader> _blocks;
  unsigned int diff;

  struct hashPredicate {
    const uint256 hash;
    explicit hashPredicate(const uint256 &hash) : hash(hash) {}

    bool operator()(const CBlockHeader &header) {
      return header.GetHash() == hash;
    }
  };

 public:
    explicit BlockFIFO(unsigned difficulty=0) : diff(difficulty) {
        if (diff == 0) {
            LL_WARNING("using difficulty %d", diff);
        }
    }
  errno_t is_valid_successor(const CBlockHeader &new_block) const {
    if (_blocks.empty()) {
        LL_DEBUG("empty");
        return NO_ERROR;
    }

    CBlockHeader prev_block = _blocks.back();

    if (prev_block.GetHash() != new_block.hashPrevBlock) {
      return BLOCKFIFO_NOT_A_CHAIN;
    }

    if (nLeadingZero(new_block.GetHash()) < diff) {
        LL_CRITICAL("insufficient diff %d (ret=%d)", nLeadingZero(new_block.GetHash()), BLOCKFIFO_INSUFFICIENT_DIFFICULTY);
      return BLOCKFIFO_INSUFFICIENT_DIFFICULTY;
    }

    return 0;
  }

  const CBlockHeader *find_block(const uint256 &hash) {
    auto it = find_if(_blocks.begin(), _blocks.end(), hashPredicate(hash));
    if (it == _blocks.end())
      return nullptr;

    return &(*it);
  }

  errno_t enqueue(const CBlockHeader &new_header) {
    errno_t ret = is_valid_successor(new_header);

    if (NO_ERROR != ret) {
      return ret;
    }

    int nPoped = 0;
    while (_blocks.size() >= QUEUE_LENGTH) {
      _blocks.pop_front();
      nPoped++;
    }

    if (nPoped > 0) {
      LL_DEBUG("removed %d blocks from FIFO", nPoped);
    }

    _blocks.push_back(new_header);
    LL_LOG("pushed");
    return NO_ERROR;
  }

  uint256 last_block() const { return _blocks.back().GetHash(); }

  size_t size() const { return _blocks.size(); }
};

#endif // TESSERACT_BLOCKFIFO_H
