#include "blockfifo.h"
#include "pprint.h"
#include "Log.h"
#include "bitcoin/utilstrencodings.h"
#include "bytestream.h"
#include "hash.h"

#include <vector>

BlockFIFO<5> bitcoinFIFO;

unsigned int nLeadingZero(const uint256 &hash) {
  std::size_t foundNonZero = hash.GetHex().find_first_not_of("0", 0);
  if (foundNonZero == std::string::npos) {
    return hash.size();
  }
  return static_cast<unsigned int>(foundNonZero);
}

void appendBlockToFIFO(const char *blockHeaderHex) {
  // sanity check
  if (2 * HeaderSize::bitcoin != strlen(blockHeaderHex)) {
    return;
    LL_CRITICAL("invalid header");
  }

  CBlockHeader block_header;

  // parse hex and unserialize
  std::vector<unsigned char> header_bin = ParseHex(blockHeaderHex);
  bytestream ibs(header_bin);
  block_header.Unserialize(ibs);

  LL_DEBUG("done unserilize");

  uint256 block_hash;
  CHash256 _hash_ctx;
  _hash_ctx.Write(header_bin.data(), header_bin.size());
  _hash_ctx.Finalize((unsigned char *) &block_hash);

  if (block_hash != block_header.GetHash()) {
    LL_CRITICAL("invalid header: wrong hash");
    throw invalid_argument("header has wrong hash");
  }

  // try to push it to the FIFO
  if(bitcoinFIFO.AppendBlock(block_header)) {
    LL_NOTICE("succeed");
  }
  else
    LL_CRITICAL("faild to append block %s", block_hash.GetHex().c_str());

  LL_NOTICE("%d blocks in FIFO", bitcoinFIFO.size());
}
