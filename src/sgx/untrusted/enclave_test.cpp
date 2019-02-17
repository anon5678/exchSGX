#include "Enclave_u.h"
#include "Utils.h"
#include "bitcoindrpcclient.h"

#include <iostream>
#include <utility>
#include "../common/utils.h"
#include "merkpath/merkpath.h"

using namespace std;

sgx_enclave_id_t eid;

void test_merkle_verify(sgx_enclave_id_t eid)
{
  const vector<string> inp1{
      "1141217f7db1bd3f3d098310e6f707eb249736cdf31ce3400705fa72bbc524f0",
      "a3f83c7f6e77ce74c978b3d42fd46a38863fb1f8170feb162382e634e9fd4336",
      "65650a7ab3da07409fa7833958f83df9327f02bd3f703322b7b973935c2c08f1",
      "a0819a177c89b04e3bbb2710e2d89007da32f09f705718cb9e85a7dcc464e3e6",
      "585ae7e330f29a13ddeca437c948489de8d885fec32684f2131d24cd854a0593"};
  const vector<string> path1{
      "e6e364c4dca7859ecb1857709ff032da0790d8e21027bb3b4eb0897c179a81a0",
      "396d16d4747f871a1528a0425f9db4023a49aa9dba3345decd8fbee0180f472f",
      "a3b4fb0ca4f26695bd61b5835458d9c9f4bfb75602c2173211e19eb2f0bcb29d"};
  const vector<string> path2{
      string(),
      string(),
      "10b038ab01c5f4048ebe7b4b66def9725dbd29d6f571474ac0c95949f74113d3"};
  // merkGenPath(inp1, 2);
  MerkleProof proof = loopMerkleProof(inp1, 4);
  proof.output(cout);
  proof.verify();

  auto p = merkle_proof_init(proof.proof_size());

  proof.serialize(p);

  merkle_proof_dump(p);

  int ret;
  merkle_proof_verify(eid, &ret, p);

  merkle_proof_free(p);

  MerkleProof proof2(inp1[2], path1, 13 /* 1RLR=1101 */);
  proof2.output(cout);
  cout << "root: " << proof2.verify() << endl;

  MerkleProof proof3(inp1[4], path2, 8 /* 1Lxx=10xx */);
  proof3.output(cout);
  proof3.verify();
  cout << "root: " << proof3.verify() << endl;
}

#include <log4cxx/logger.h>
#include <log4cxx/propertyconfigurator.h>

namespace exch
{
namespace enclave_test
{
log4cxx::LoggerPtr logger(log4cxx::Logger::getLogger("exch.enclave_test"));
}
}  // namespace exch

using exch::enclave_test::logger;

int main()
{
  log4cxx::PropertyConfigurator::configure(LOGGING_CONF);

  sgx_status_t st;

  if (0 != initialize_enclave(&eid)) {
    cerr << "failed to init enclave" << endl;
    exit(-1);
  }

  int ret;

  st = enclaveTest(eid, &ret);
  if (st != SGX_SUCCESS || ret != 0) {
    LOG4CXX_ERROR(
        logger, "failed to run enclave test: st=" << st << " ret=" << ret);
  }

  // test_merkle_verify(eid);
}