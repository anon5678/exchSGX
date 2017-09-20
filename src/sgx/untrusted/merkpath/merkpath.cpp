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

typedef unsigned long long cointype;

log4cxx::LoggerPtr logger(log4cxx::Logger::getLogger("merkleproof"));

void hexdump(const unsigned char *data, int len) {
  std::cout << std::hex;
  for (int i = 0; i < len; ++i)
    std::cout << std::setfill('0') << std::setw(2) << (int) data[i];
  std::cout << std::dec << std::endl;
}

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

void hash160(void const *const src, int len, void *const dst) {
  SHA256_CTX h1;
  unsigned char tmp[SHA256_DIGEST_LENGTH];
  SHA256_Init(&h1);
  SHA256_Update(&h1, (unsigned char *) src, len);
  SHA256_Final(tmp, &h1);
  RIPEMD160_CTX h2;
  RIPEMD160_Init(&h2);
  RIPEMD160_Update(&h2, tmp, SHA256_DIGEST_LENGTH);
  RIPEMD160_Final((unsigned char *) dst, &h2);
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

void MerkleProof::serialize() {
  // 1. put in the tx
  hex2bin(serialized.tx, tx.c_str());

  // 2. put in the merkle branch
  serialized.merkle_branch_len = BITCOIN_HASH_LENGTH * branch.size();

  for (auto i = 0; i < branch.size(); i++) {
    printf("serialize: %p\n", serialized.merkle_branch);
    serialized.merkle_branch[i] = (bitcoin_hash_t*) malloc(BITCOIN_HASH_LENGTH);
    printf("serialize: %p\n", serialized.merkle_branch[i]);
    if (branch[i].empty()) {
      cerr << "dealing with empty" << endl;
      memset(serialized.merkle_branch[i], 0x00, BITCOIN_HASH_LENGTH);
    }
    else
      hex2bin((unsigned char*) serialized.merkle_branch[i], branch[i].c_str());
  }

  printf("done\n");

  // 3. put in the dir vec
  serialized.dirvec = direction;

  // 4. put in the block hash. TODO
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

bool MerkleProof::verify(){
  sha256buf curr;
  sha256buf tmp;

  hex2bin(curr.data(),  tx.c_str());
  byte_swap(curr.data(), 32);

  for (int i = 0; direction > 1; ++i, direction >>= 1) {
    if ((branch[i]).empty()) {
      sha256double(curr.data(), curr.data(), curr.data());
      continue;
    }
    //std::memcpy(tmp, (base64_decode(branch[i])).data(), 32);
    hex2bin(tmp.data(), branch[i].c_str());
    if (direction & 1)
      sha256double(curr.data(), tmp.data(), curr.data());
    else
      sha256double(tmp.data(), curr.data(), curr.data());
  }

  cout << "verify: ";
  byte_swap(curr.data(), 32);
  hexdump(curr.data(), 32);
}

#if 0
void fill_timelock_payment_template(unsigned char *aa, const char *RTEpk,
                                    int timeout, const char *refund) {
  int j = 0;
  aa[j++] = 0x63; // op_if
  aa[j++] = 0xa8; // op_sha256 (rm)
  aa[j++] = 0x20; // 32 bytes digest size (rm)
  std::memcpy(
      aa + j,
      (base64_decode("x3Xnt1ft5jDNCqERO9ECZhqziCnKUqZCKreChi8mhkY=")).data(),
      32);           // sha256 digest (rm)
  aa[j + 32] = 0x88; // op_equalverify (rm)
  j += 33;
  aa[j++] = 0x21; // 33 bytes pubkey size
  std::memcpy(aa + j, RTEpk, 33);
  aa[j + 33] = 0xAC; // op_checksig
  j += 34;
  aa[j++] = 0x67; // op_else
  aa[j++] = 0x3;  // timeout size
  aa[j++] = timeout >> 16;
  aa[j++] = timeout >> 8;
  aa[j++] = timeout;
  aa[j++] = 0xb1; // op_CLTV
  aa[j++] = 0x75; // op_drop
  aa[j++] = 0x21; // 33 bytes pubkey size
  std::memcpy(aa + j, refund, 33);
  aa[j + 33] = 0xAC; // op_checksig
  aa[j + 34] = 0x68; // op_endif
}

cointype validateDeposit(const unsigned char *tx, const char *RTEpubkey,
                         int timeout, const char *refund) {
  if (1 != tx[4])
    return 0;                                      // single input
  int j = 5 + 32 + 4 + 1 + tx[5 + 32 + 4] + 4 + 1; // skip to first output
  cointype r = tx[j++];
  for (int i = 8; i <= 56; i += 8)
    r += cointype(tx[j++]) << i;
  if (23 != tx[j++])
    return 0; // p2sh size
  if (0xA9 != tx[j++])
    return 0; // op_hash160
  if (0x14 != tx[j++])
    return 0; // 20 bytes
  if (0x87 != tx[j + 20])
    return 0; // op_equal
  hexdump(tx + j, 20);

  unsigned char arr[114];
  fill_timelock_payment_template(arr, RTEpubkey, timeout, refund);
  unsigned char res[20];
  hash160(arr, 114, res);
  hexdump(res, 20);

  return r;
}
#endif

#include "../rpc.h"
#include "../Utils.h"

void verify_merkle_proof(const std::string &leaf, const vector<string>& branch, int dirvec) {
  unsigned char curr[SHA256_DIGEST_LENGTH];
  unsigned char tmp[SHA256_DIGEST_LENGTH];

  //std::memcpy(curr, (base64_decode(leaf)).data(), 32);
  hex2bin(curr, leaf.c_str());
  byte_swap(curr, 32);

  for (int i = 0; dirvec > 1; ++i, dirvec >>= 1) {
    if ((branch[i]).empty()) {
      sha256double(curr, curr, curr);
      continue;
    }
    //std::memcpy(tmp, (base64_decode(branch[i])).data(), 32);
    hex2bin(tmp, branch[i].c_str());
    if (dirvec & 1)
      sha256double(curr, tmp, curr);
    else
      sha256double(tmp, curr, curr);
  }

  byte_swap(curr, 32);
  hexdump(curr, 32);
}


static void testMerk() {
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
  loopMerkleProof(inp1, 4).output(cout);
  verify_merkle_proof(inp1[2], path1, 13 /* 1RLR=1101 */);
  verify_merkle_proof(inp1[4], path2, 8 /* 1Lxx=10xx */);
}


int main(int argc, const char *argv[]) {
  if (argc < 2) {
    cout << "Usage: " << argv[0] << " txid" << endl;
    exit(-1);
  }

  testMerk();

  log4cxx::PropertyConfigurator::configure(LOGGING_CONF);
  LOG4CXX_INFO(logger, "starting merkle proof");

  bitcoinRPC rpc;

  string txid = string(argv[1]);

  try {
    Json::Value txn = rpc.getrawtransaction(txid, true);

    if (!txn.isMember("blockhash")) {
      throw runtime_error("invalid txn");
    }

    string block_hash = txn["blockhash"].asString();
    Json::Value block = rpc.getblock(block_hash);
    vector<string> merkle_leaves;

    if (!block.isMember("tx")) {
      throw runtime_error("invalid txn");
    }
    for (auto tx : block["tx"]) {
      merkle_leaves.push_back(tx.asString());
    }

    auto tx_idx = distance(
        merkle_leaves.begin(),
        find(merkle_leaves.begin(), merkle_leaves.end(), txid));

    if (tx_idx >= merkle_leaves.size()) {
      throw runtime_error("invalid block");
    };

    LOG4CXX_INFO(logger, "Generating proof for tx (index="
                           << tx_idx
                           << ") in block #"
                           << block["height"]);

    MerkleProof proof = loopMerkleProof(merkle_leaves, tx_idx);

    proof.output(cout);
    proof.verify();
    proof.serialize();

    LOG4CXX_INFO(logger, "Merkle root of block #" << block["height"] << ": " << block["merkleroot"].asString());
  } catch (const bitcoinRPCException &e) {
    LOG4CXX_ERROR(logger, e.what());
    return -1;
  }
  return 0;
}

