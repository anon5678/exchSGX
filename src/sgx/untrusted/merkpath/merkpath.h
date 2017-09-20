#ifndef EXCH_MERKPATH_H
#define EXCH_MERKPATH_H

#include <string>
#include <vector>
#include <ostream>
#include <array>

#include "../../common/merkle_data.h"
#include <string.h>
#include <iostream>

using std::vector;
using std::string;
using std::array;
using std::cout;
using std::endl;
using std::ostream;

constexpr size_t SHA256_DIGEST_LENGTH = 32;
using sha256buf = array<unsigned char, SHA256_DIGEST_LENGTH>;

void merkGenPath(const vector<string> &leaf_nodes, int index);

class MerkleProof {
 private:
  static constexpr const char* BEGIN = "---BEGIN MERKLEPROOF---";
  static constexpr const char* END = "---END MERKLEPROOF---";

  string tx;
  vector<string> branch;
  int direction;

  merkle_proof_t serialized;

 public:

  MerkleProof(const string& tx, const vector<string>& branch, int dirvec)
  : tx(tx), branch(branch), direction(dirvec){
    memset(&serialized, 0x00, sizeof (merkle_proof_t));
  }

  ~MerkleProof(){
    if (!serialized.merkle_branch)
      return;
    for (int i =0; i < serialized.merkle_branch_len; i++) {
      if (serialized.merkle_branch[i]) {
        free(serialized.merkle_branch[i]);
      }
    }
  }

  const merkle_proof_t* getSerialized() {
    return &serialized;
  }

  void output(ostream& out) {
    if (direction < 0) {
      out << "error" << endl;
    }
    out << BEGIN << endl;
    for (auto& s : branch) {
      out << s << endl;
    }

    out << direction << endl;
    out << END << endl;
  }

  void serialize();

  bool verify();
};

#endif /* ifndef  EXCH_MERKPATH_H */
