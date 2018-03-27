#ifndef TESSERACT_BITCOIND_MERKLEPROOF_H
#define TESSERACT_BITCOIND_MERKLEPROOF_H

#include <string>
#include "merkpath/merkpath.h"

MerkleProof buildTxInclusionProof(const std::string& txid);

#endif //TESSERACT_BITCOIND_MERKLEPROOF_H
