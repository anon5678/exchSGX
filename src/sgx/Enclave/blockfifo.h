#ifndef TESSERACT_BLOCKFIFO_H
#define TESSERACT_BLOCKFIFO_H

#include <deque>

#include "bitcoin_helpers.h"

#include "../common/errno.h"
#include "bitcoin/primitives/block.h"
#include "exception.h"
#include "pprint.h"

using std::deque;
using std::pair;

// initialized data
enum HeaderSize {
  bitcoin = 80,
};

template <unsigned int QUEUE_LENGTH>
class BlockFIFO
{
 private:
  deque<CBlockHeader> _blocks;
  unsigned int min_difficulty;

  struct hashPredicate {
    const uint256 hash;
    explicit hashPredicate(const uint256 &hash) : hash(hash) {}

    bool operator()(const CBlockHeader &header)
    {
      return header.GetHash() == hash;
    }
  };

 public:
  explicit BlockFIFO(unsigned difficulty = 0) : min_difficulty(difficulty)
  {
    if (min_difficulty == 0) {
      LL_WARNING("using difficulty %d", min_difficulty);
    }
  }
  errno_t is_valid_successor(const CBlockHeader &new_block) const;

  //! find if a block hash in in the fifo and return the number of confirmations of it.
  //! it throws invalid_argument if no such a block is in the FIFO
  //! \param hash block hash to be found
  //! \return a pair of a reference to the block and the # of the confirmations.
  pair<const CBlockHeader &, int> find_block(const uint256 &hash) noexcept(
      false);

  void try_append_new_block(const CBlockHeader &new_header) noexcept(false);

  uint256 first_block() const { return _blocks.front().GetHash(); }

  uint256 last_block() const { return _blocks.back().GetHash(); }

  size_t size() const { return _blocks.size(); }
};

template <unsigned int Q>
errno_t BlockFIFO<Q>::is_valid_successor(const CBlockHeader &new_block) const
{
  if (_blocks.empty()) {
    LL_LOG("empty");
    return NO_ERROR;
  }

  CBlockHeader prev_block = _blocks.back();

  if (prev_block.GetHash() != new_block.hashPrevBlock) {
    return BLOCKFIFO_NOT_A_CHAIN;
  }

  if (get_num_of_leading_zeroes(new_block.GetHash()) < min_difficulty) {
    LL_CRITICAL(
        "insufficient diff %d (ret=%d)",
        get_num_of_leading_zeroes(new_block.GetHash()),
        BLOCKFIFO_INSUFFICIENT_DIFFICULTY);
    return BLOCKFIFO_INSUFFICIENT_DIFFICULTY;
  }

  return 0;
}

template <unsigned int Q>
pair<const CBlockHeader &, int> BlockFIFO<Q>::find_block(const uint256 &hash)
{
  auto it = find_if(_blocks.begin(), _blocks.end(), hashPredicate(hash));
  if (it == _blocks.end()) {
    throw std::invalid_argument("hash not in FIFO");
  }

  // minus one to make the latest block to have zero confirmations
  return std::make_pair(*it, std::distance(it, _blocks.end()) - 1);
}

template <unsigned int Q>
void BlockFIFO<Q>::try_append_new_block(
    const CBlockHeader &new_header) noexcept(false)
{
  errno_t ret = is_valid_successor(new_header);

  if (NO_ERROR != ret) {
    throw exch::enclave::Exception(ret, "invalid successor");
  }

  int n_poped_headers = 0;
  while (_blocks.size() >= Q) {
    _blocks.pop_front();
    n_poped_headers++;
  }

  if (n_poped_headers > 0) {
    LL_DEBUG("removed %d blocks from FIFO", n_poped_headers);
  }

  _blocks.push_back(new_header);
}

#endif  // TESSERACT_BLOCKFIFO_H
