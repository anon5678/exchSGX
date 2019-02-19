#ifndef TESSERACT_BITCOIND_MERKLEPROOF_H
#define TESSERACT_BITCOIND_MERKLEPROOF_H

#include <string>
#include "merkpath/merkpath.h"

enum TxInclusion {
  Yes,
  No,
  NotSure,
};

bool getConfirmedHeader(const std::string &txid, const int NUM_CONFIRMATION, unsigned char* header);
string getRawTransaction(const std::string &txid);
MerkleProof buildTxInclusionProof(const std::string &txid);
TxInclusion isTxIncluded(const string &txid);

#endif  // TESSERACT_BITCOIND_MERKLEPROOF_H
