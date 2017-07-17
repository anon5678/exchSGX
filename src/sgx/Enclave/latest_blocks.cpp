//
// Created by fanz on 7/13/17.
//

#include "latest_blocks.h"
#include "pprint.h"
#include "Log.h"
#include "bitcoin/utilstrencodings.h"
#include "bytestream.h"
#include "hash.h"

#include <vector>

constexpr size_t HEADER_SIZE = 80;

LatestBlocks<5> blockchain;

extern "C" {
void push(const char *);
}

void push(const char *block_hdr_hex) {
  // sanity check
  if (2 * HEADER_SIZE != strlen(block_hdr_hex)) {
    return;
    LL_CRITICAL("invalid header");
  }

  CBlockHeader block_header;

  // parse hex and unserialize
  std::vector<unsigned char> header_bin = ParseHex(block_hdr_hex);
  bytestream ibs(header_bin);
  block_header.Unserialize(ibs);

  LL_DEBUG("done unserilize");

  uint256 block_hash;
  CHash256 _hash_ctx;
  _hash_ctx.Write(header_bin.data(), header_bin.size());
  _hash_ctx.Finalize((unsigned char *) &block_hash);

  // serialize again to ensure integrity
  LL_LOG("old hash: %s", block_hash.GetHex().c_str());
  LL_LOG("rehash: %s", block_header.GetHash().GetHex().c_str());

  assert(block_hash == block_header.GetHash());

  // try to push it to the blockchain
  if(blockchain.AppendBlock(block_header)) {
    LL_NOTICE("succeed");
  }
  else
    LL_CRITICAL("faild to append block %s", block_hash.GetHex().c_str());

  LL_NOTICE("%d blocks in FIFO", blockchain.size());
}
