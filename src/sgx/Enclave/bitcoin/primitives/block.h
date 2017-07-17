// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2016 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_PRIMITIVES_BLOCK_H
#define BITCOIN_PRIMITIVES_BLOCK_H

#include "serialize.h"
#include "uint256.h"

#include "Log.h"

/** Nodes collect new transactions into a block, hash them into a hash tree,
 * and scan through nonce values to make the block's hash satisfy proof-of-work
 * requirements.  When they solve the proof-of-work, they broadcast the block
 * to everyone and the block is added to the block chain.  The first transaction
 * in the block is a special one that creates a new coin owned by the creator
 * of the block.
 */
class CBlockHeader {
 public:
  // header
  int32_t nVersion;
  uint256 hashPrevBlock;
  uint256 hashMerkleRoot;
  uint32_t nTime;
  uint32_t nBits;
  uint32_t nNonce;

  CBlockHeader() {
    SetNull();
  }

  ADD_SERIALIZE_METHODS;

  template<typename Stream, typename Operation>
  inline void SerializationOp(Stream &s, Operation ser_action) {
    READWRITE(this->nVersion);
    READWRITE(hashPrevBlock);
    READWRITE(hashMerkleRoot);
    READWRITE(nTime);
    READWRITE(nBits);
    READWRITE(nNonce);
  }

  void SetNull() {
    nVersion = 0;
    hashPrevBlock.SetNull();
    hashMerkleRoot.SetNull();
    nTime = 0;
    nBits = 0;
    nNonce = 0;
  }

  bool IsNull() const {
    return (nBits == 0);
  }

  uint256 GetHash() const;

  int64_t GetBlockTime() const {
    return (int64_t) nTime;
  }
};

#endif // BITCOIN_PRIMITIVES_BLOCK_H
