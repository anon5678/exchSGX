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
constexpr size_t HASH_SIZE = 32;

LatestBlocks<5> blockchain;

extern "C" {
void push(const char *);
}

void push(const char *header_hex) {
  // sanity check
  if (2 * HEADER_SIZE != strlen(header_hex)) {
    return;
    LL_CRITICAL("invalid header");
  }

  CBlockHeader block_header;

  // parse hex and unserialize
  std::vector<unsigned char> header_bin = ParseHex(header_hex);
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

  // push it to the blockchain
  if(blockchain.push(block_header)) {
    LL_NOTICE("block %s pushed", block_hash.GetHex().c_str());
    LL_NOTICE("%d blocks in queue", blockchain.size());
  }
  else
    LL_NOTICE("faild to push %s", block_hash.GetHex().c_str());
}
