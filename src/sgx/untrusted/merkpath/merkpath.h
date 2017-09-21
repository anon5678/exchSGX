#ifndef EXCH_MERKPATH_H
#define EXCH_MERKPATH_H

#include <string>
#include <vector>
#include <ostream>
#include <array>

#include "../../common/merkle_data.h"
#include <iostream>
#include <stdexcept>

using std::vector;
using std::string;
using std::array;
using std::cout;
using std::endl;
using std::ostream;
using std::invalid_argument;

constexpr size_t SHA256_DIGEST_LENGTH = 32;
using sha256buf = array<unsigned char, SHA256_DIGEST_LENGTH>;

void merkGenPath(const vector<string> &leaf_nodes, int index);

#include <json/json.h>

class MerkleProof {
 private:
  static constexpr const char* BEGIN = "---BEGIN MERKLEPROOF---";
  static constexpr const char* END = "---END MERKLEPROOF---";

  string tx;
  vector<string> branch;
  int direction;

  // helper data
  // in particular, these are not necessary but it helps
  string block;

 public:
  MerkleProof(const string& tx, const vector<string>& branch, int dirvec)
      : tx(tx), branch(branch), direction(dirvec){
    for (auto& b : branch) {
      if (b.size() != 2 * BITCOIN_HASH_LENGTH) {
        throw invalid_argument("branch " + b + " doesn't have 64 letters");
      }
    }
  }
  MerkleProof(const string& tx, vector<string>&& branch, int dirvec)
  : tx(tx), branch(branch), direction(dirvec){
  }

  ~MerkleProof() = default;

  size_t proof_size() {
    return branch.size();
  }

  void set_block(const string& value) {
    block = value;
  }

  void dumpJSON(ostream& out) {
    Json::Value proof;
    proof["tx"] = tx;
    proof["block"] = block;
    proof["dirvec"] = direction;
    proof["branch"] = Json::arrayValue;

    for (auto & b: branch) {
      proof["branch"].append(b);
    }

    out << proof;
  }

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
  string verify() const;
};

void testMerk();
MerkleProof loopMerkleProof(const vector<string> &leaf_nodes, long index);

#endif /* ifndef  EXCH_MERKPATH_H */
