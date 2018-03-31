#ifndef TESSERACT_BITCOIND_MERKLEPROOF_H
#define TESSERACT_BITCOIND_MERKLEPROOF_H

#include <string>
#include "merkpath/merkpath.h"

enum TxInclusion {
  Yes,
  No,
  NotSure,
};

MerkleProof buildTxInclusionProof(const std::string& txid);
TxInclusion isTxIncluded(const string &txid);

#endif //TESSERACT_BITCOIND_MERKLEPROOF_H
