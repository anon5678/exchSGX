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
  static constexpr const char *BEGIN = "---BEGIN MERKLEPROOF---";
  static constexpr const char *END = "---END MERKLEPROOF---";

  string tx_hash_hex;
  vector<string> branch;
  int direction;

  // helper data. not necessary but it helps
  // block_hash
  string block_hash_hex;
  string tx_raw_hex;

 public:
  MerkleProof(const string &tx, const vector<string> &branch, int dirvec)
      : tx_hash_hex(tx), branch(branch), direction(dirvec) {
    for (auto &b : branch) {
      if (!b.empty() && b.size() != 2 * BITCOIN_HASH_LENGTH) {
        throw invalid_argument("branch " + b + " doesn't have 64 letters");
      }
    }
  }
  MerkleProof(const string &tx, vector<string> &&branch, int dirvec)
      : tx_hash_hex(tx), branch(branch), direction(dirvec) {
  }

  ~MerkleProof() = default;

  size_t proof_size() {
    return branch.size();
  }

  void set_block(const string &value) {
    block_hash_hex = value;
  }

  void set_tx_raw(const string& value) {
    tx_raw_hex = value;
  }

  void dumpJSON(ostream &out) {
    Json::Value proof;
    proof["tx"] = tx_hash_hex;
    proof["tx_raw"] = tx_raw_hex;
    proof["block"] = block_hash_hex;
    proof["dirvec"] = direction;
    proof["branch"] = Json::arrayValue;

    for (auto &b: branch) {
      proof["branch"].append(b);
    }

    out << proof;
  }

  void output(ostream &out) const {
    if (direction < 0) {
      out << "error" << endl;
      return;
    }
    out << BEGIN << endl;
    for (auto &s : branch) {
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
