#include "state.h"

#include "bitcoin/utilstrencodings.h"
#include "blockfifo.h"
#include "hash.h"
#include "log.h"
#include "pprint.h"
#include "state.h"

#include <vector>
#include "../common/errno.h"
#include "bitcoin/streams.h"

using namespace exch::enclave;

int ecall_append_block_to_fifo(uint16_t index, const char *blockHeaderHex)
{
  try {
    // sanity check
    if (2 * HeaderSize::bitcoin != strlen(blockHeaderHex)) {
      LL_CRITICAL("invalid header");
      return BLOCKFIFO_INVALID_INPUT;
    }

    // parse hex and deserialize
    std::vector<unsigned char> header_bin = ParseHex(blockHeaderHex);
    CBlockHeader block_header;
    CDataStream _in(header_bin, SER_NETWORK, PROTOCOL_VERSION);
    _in >> block_header;

    uint256 block_hash;
    CHash256 _hash_ctx;
    _hash_ctx.Write(header_bin.data(), header_bin.size());
    _hash_ctx.Finalize(block_hash.begin());

    if (block_hash != block_header.GetHash()) {
      LL_CRITICAL("invalid header: wrong hash");
      return BLOCKFIFO_INVALID_INPUT;
    }

    // try to push it to the FIFO. throw if fails.
    state::blockFIFO[index - 1].try_append_new_block(block_header);
    //LL_NOTICE("block %s appended.", block_header.GetHash().ToString().c_str());

    auto confirms = state::blockFIFO[index - 1].find_block(state::blockFIFO[index - 1].first_block());

    LL_LOG(
        "%d blocks in queue. the head has %d confirmations",
        state::blockFIFO[index - 1].size(),
        confirms.second);

    return NO_ERROR;

  } catch (const exch::enclave::Exception &e) {
    LL_CRITICAL("failed to append block. error code: %d", e.getErrorCode());
    return e.getErrorCode();
  }
  CATCH_STD_AND_ALL_NO_RET

  return ECALL_UNKNOWN_ERROR;
}

int ecall_get_latest_block_hash(uint16_t index, unsigned char *o_buf, size_t cap_obuf)
{
  uint256 last = state::blockFIFO[index - 1].last_block();
  if (cap_obuf < last.size()) {
    LL_CRITICAL("buffer too small");
    return ECALL_BUFFER_TOO_SMALL;
  }
  memcpy(o_buf, last.begin(), last.size());
  return NO_ERROR;
}
