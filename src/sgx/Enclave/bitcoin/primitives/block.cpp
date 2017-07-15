// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2016 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "primitives/block.h"

#include "hash.h"
#include "utilstrencodings.h"
#include "crypto/common.h"

#include <exception>

uint256 CBlockHeader::GetHash() const
{
  throw std::invalid_argument("not implemented");
//    return SerializeHash(*this);
}
