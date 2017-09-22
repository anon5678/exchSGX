#include "merkpath.h"
#include "../../common/merkle_data.h"
#include "../../common/utils.h"

#include <cstring>
#include <iomanip>
#include <iostream>
#include <openssl/ripemd.h>
#include <openssl/sha.h>
#include <iostream>
#include <algorithm>
#include <array>
#include <stdexcept>

#include <log4cxx/logger.h>
#include <log4cxx/propertyconfigurator.h>

using namespace std;

namespace exch {
namespace merkpath {
log4cxx::LoggerPtr logger(log4cxx::Logger::getLogger("merkpath.merkpath"));
}
}

using exch::merkpath::logger;

#if 0
void hexdump(const unsigned char *data, int len) {
  std::cout << std::hex;
  for (int i = 0; i < len; ++i)
    std::cout << std::setfill('0') << std::setw(2) << (int) data[i];
  std::cout << std::dec << std::endl;
}
#endif

string tohex(const sha256buf& data) {
  stringstream ss;
  ss << std::hex;
  for (auto d : data) {
    ss << std::setfill('0') << std::setw(2) << (int) d;
  }
  return ss.str();
}

// s1+s2 are the 32+32 bytes input, dst is 32 bytes output
void sha256double(void const *const s1, void const *const s2, void *const dst) {
  SHA256_CTX h1, h2;
  unsigned char tmp[SHA256_DIGEST_LENGTH];

  SHA256_Init(&h1);
  // if(NULL != s1)
  SHA256_Update(&h1, (unsigned char *) s1, SHA256_DIGEST_LENGTH);
  // if(NULL != s2)
  SHA256_Update(&h1, (unsigned char *) s2, SHA256_DIGEST_LENGTH);
  SHA256_Final(tmp, &h1);

  SHA256_Init(&h2);
  SHA256_Update(&h2, tmp, SHA256_DIGEST_LENGTH);
  SHA256_Final((unsigned char *) dst, &h2);
}



MerkleProof loopMerkleProof(const vector<string> &leaf_nodes, long index) {
  LOG4CXX_ASSERT(logger, leaf_nodes.size() > 1, "need at least two transactions");
  LOG4CXX_ASSERT(logger, index >= 0 && index < leaf_nodes.size(), "index overflow");
  LOG4CXX_ASSERT(logger, leaf_nodes[0].size() == 64, "please use hex string");

  size_t size, next_level_size;
  size = leaf_nodes.size();

  vector<sha256buf> level;
  vector<sha256buf> next_level;

  level.resize(size);

  for (int i = 0; i < size; ++i) {
    hex2bin(level[i].data(), leaf_nodes[i].c_str());
    byte_swap(level[i].data(), SHA256_DIGEST_LENGTH);
  }

  vector<string> proof_merkle_branch;

  long path = index;
  int dirvec = 0;
  int position = 0;

  do {
    size = level.size();
    next_level_size = (size + (size & 1)) / 2;

    next_level.clear();
    next_level.resize(next_level_size);

    for (int i = 0; i < next_level_size; ++i) {
      auto left_node = &level[2*i];
      auto right_node = ((2 * i + 1) == size ? left_node : &level[2 * i + 1]);

      sha256double(left_node->data(), right_node->data(), next_level[i].data());
      if (path == (2 * i + 1)) {
        proof_merkle_branch.push_back(tohex(*left_node));
        continue;
      }
      if (path == (2 * i)) {
        if (left_node != right_node) {
          proof_merkle_branch.push_back(tohex(*right_node));
          dirvec |= (1 << position);
        } else {
          // append empty string
          proof_merkle_branch.push_back("");
        }
      }
    }

    // enter the next level
    level.clear();
    copy(next_level.begin(), next_level.end(), back_inserter(level));

    path /= 2;
    position += 1;
  } while (level.size() > 1);

  dirvec |= (1 << position);
  MerkleProof proof(leaf_nodes[index], proof_merkle_branch, dirvec);

  // byte_swap(level[0].data(), SHA256_DIGEST_LENGTH);
  // hexdump(level[0].data(), SHA256_DIGEST_LENGTH);

  return proof;
}

void MerkleProof::serialize(merkle_proof_t *o) const {
  if (!o) return;
  // 1. put in the tx
  hex2bin(o->tx, tx_hash_hex.c_str());
  // swap from RPC order -> little endian
  byte_swap(o->tx, sizeof o->tx);

  // 2. put in the tx_raw
  o->tx_raw_hex = tx_raw_hex.c_str();

  // 3. put in the merkle branch
  if (o->merkle_branch_len != branch.size()) {
    throw runtime_error("output buffer too small");
  }

  for (int i = 0; i < branch.size(); i++) {
    if (branch[i].empty()) {
      o->merkle_branch[i] = nullptr;
    }
    else {
      o->merkle_branch[i] = (bitcoin_hash_t*) malloc(BITCOIN_HASH_LENGTH);
      hex2bin((unsigned char*) o->merkle_branch[i], branch[i].c_str());
    }
  }

  // 4. put in the dir vec
  o->dirvec = direction;
}

#if 0
void recursiveMerk(const vector<sha256buf>& level, int path, int dirvec, int position) {
  size_t size = level.size();
  size_t k = (size + (size & 1)) / 2;

  vector<sha256buf> next_level;
  next_level.resize(k);

  for (int i = 0; i < k; ++i) {
    auto left_node = &level[2*i];
    auto right_node = ((2 * i + 1) == size ? left_node : &level[2 * i + 1]);

    sha256double(left_node->data(), right_node->data(), next_level[i].data());
    if (path == (2 * i + 1)) {
      //std::cout << "L: ";
      hexdump(left_node->data(), SHA256_DIGEST_LENGTH);
      continue;
    }
    if (path == (2 * i)) {
      //std::cout << "R: ";
      if (left_node != right_node) {
        hexdump(right_node->data(), SHA256_DIGEST_LENGTH);
        dirvec |= (1 << position);
      } else
        std::cout /* << "*" */ << std::endl;
    }
  }
  if (k > 1)
    recursiveMerk(next_level, path / 2, dirvec, position + 1);
  else {
    cout << (dirvec | (1 << (position + 1))) << endl;
    cout << "---END MERKLEPROOF---" << endl;
    cout << "root: ";
    byte_swap(next_level[0].data(), SHA256_DIGEST_LENGTH);
    hexdump(next_level[0].data(), SHA256_DIGEST_LENGTH);
  }
}

void merkGenPath(const vector<string> &leaf_nodes, int index) {
  LOG4CXX_ASSERT(logger, leaf_nodes.size() <= 1, "need at least two transactions");
  LOG4CXX_ASSERT(logger, index >= 0 && index < leaf_nodes.size(), "index overflow");
  LOG4CXX_ASSERT(logger, leaf_nodes[0].size() == 64, "please use hex string");

  size_t size = leaf_nodes.size();

  vector<sha256buf> mTree;
  mTree.resize(size);

  for (int i = 0; i < size; ++i) {
    hex2bin(mTree[i].data(), leaf_nodes[i].c_str());
    byte_swap(mTree[i].data(), SHA256_DIGEST_LENGTH);
  }

  cout << "---BEGIN MERKLEPROOF---" << endl;
  recursiveMerk(mTree, index, 0, 0);
}
#endif

string MerkleProof::verify() const{
  sha256buf curr;
  sha256buf tmp;

  hex2bin(curr.data(),  tx_hash_hex.c_str());
  byte_swap(curr.data(), 32);

  if (!tx_raw_hex.empty())
  {
    auto tx_raw_bin = hex2bin(tx_raw_hex.c_str());

    SHA256_CTX h1,h2;
    unsigned char t1[SHA256_DIGEST_LENGTH];
    SHA256_Init(&h1);
    SHA256_Update(&h1, tx_raw_bin.data(), tx_raw_bin.size());
    SHA256_Final(t1, &h1);

    SHA256_Init(&h2);
    SHA256_Update(&h2, t1, SHA256_DIGEST_LENGTH);
    SHA256_Final(t1, &h2);

    byte_swap(t1, sizeof t1);

    auto tx_hash_calc = bin2hex(t1, sizeof t1);

    if (tx_hash_calc != tx_hash_hex) {
      LOG4CXX_WARN(logger, "incorrect tx hash?");
      LOG4CXX_WARN(logger, "expected: " << tx_hash_hex);
      LOG4CXX_WARN(logger, "calc: " << tx_hash_calc);
    }
  }

  // make a copy of direction
  int dirvec = direction;

  for (int i = 0; dirvec > 1; ++i, dirvec >>= 1) {
    if ((branch[i]).empty()) {
      sha256double(curr.data(), curr.data(), curr.data());
      continue;
    }
    hex2bin(tmp.data(), branch[i].c_str());
    if (dirvec & 1)
      sha256double(curr.data(), tmp.data(), curr.data());
    else
      sha256double(tmp.data(), curr.data(), curr.data());
  }

  byte_swap(curr.data(), 32);

  return tohex(curr);
}

#if 0

#endif


void testMerk() {
  // b42be2d0403e5a7336b1f5e2b5c344827177d191b1cbced3565b7ba138d8a83d
  const vector<string> inp1 {
      "1141217f7db1bd3f3d098310e6f707eb249736cdf31ce3400705fa72bbc524f0",
      "a3f83c7f6e77ce74c978b3d42fd46a38863fb1f8170feb162382e634e9fd4336",
      "65650a7ab3da07409fa7833958f83df9327f02bd3f703322b7b973935c2c08f1",
      "a0819a177c89b04e3bbb2710e2d89007da32f09f705718cb9e85a7dcc464e3e6",
      "585ae7e330f29a13ddeca437c948489de8d885fec32684f2131d24cd854a0593"};
  const vector<string> path1 {
      "e6e364c4dca7859ecb1857709ff032da0790d8e21027bb3b4eb0897c179a81a0",
      "396d16d4747f871a1528a0425f9db4023a49aa9dba3345decd8fbee0180f472f",
      "a3b4fb0ca4f26695bd61b5835458d9c9f4bfb75602c2173211e19eb2f0bcb29d"};
  const vector<string> path2 {string(),
                              string(),
                              "10b038ab01c5f4048ebe7b4b66def9725dbd29d6f571474ac0c95949f74113d3"};
  // merkGenPath(inp1, 2);
  MerkleProof proof = loopMerkleProof(inp1, 4);
  proof.output(cout);
  proof.verify();

  MerkleProof proof2(inp1[2], path1, 13 /* 1RLR=1101 */);
  proof2.output(cout);
  proof2.verify();

  MerkleProof proof3(inp1[4], path2, 8 /* 1Lxx=10xx */);
  proof3.output(cout);
  proof3.verify();
}



