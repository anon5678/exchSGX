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
  string block_hash;
  vector<string> branch;
  int direction;

 public:
  MerkleProof(const string& tx, const vector<string>& branch, int dirvec)
  : tx(tx), branch(branch), direction(dirvec){
  }

  ~MerkleProof() = default;

  size_t proof_size() {
    return branch.size();
  }

  void set_block_hash(const string& block_hash) { this->block_hash = block_hash; }

  void output(ostream& out) const {
    if (direction < 0) {
      out << "error" << endl;
      return;
    }
    out << BEGIN << endl;
    for (auto& s : branch) {
      out << s << endl;
    }

    out << direction << endl;
    out << END << endl;
  }

  void serialize(merkle_proof_t *o) const;
  bool verify() const;
};

void testMerk();
MerkleProof loopMerkleProof(const vector<string> &leaf_nodes, long index);

#endif /* ifndef  EXCH_MERKPATH_H */
