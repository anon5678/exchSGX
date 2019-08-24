#include "Enclave_u.h"
#include "config.h"
#include "enclave-utils.h"
#include "interrupt.h"

#define CATCH_CONFIG_MAIN
#include "external/catch.hpp"

using namespace std;
Config conf;

sgx_enclave_id_t eid;

/*
#include "rpc/bitcoind-client.h"

TEST_CASE("RPC", "[bitcoind rpc]") {
    Bitcoind client("localhost");
    REQUIRE_NOTHROW(client.getblockcount());
    REQUIRE_THROWS_AS(client.sendrawtransaction("0x"), BitcoindRPCException);
    REQUIRE_THROWS_AS(client.sendrawtransaction("020000000184b9e9fc7e0de3040d3df835c2f8a1ac603840ba07a2ae91b7349f57b49fee2700000000484730440220633e7218eb0971ec46246dc9a176239563f969ad8f7226a5cc3a90403c868ec002205c01a8e18b5ce5403447adc9a6327b5614624cd086c7347f6e1e0b6fc5d4360c01fdffffff0200ca9a3b000000001976a914567827d4bedca8a476fc0d6ab47dad54ad52379688ac3e196bee0000000017a91457e70919a54efea88b9e222d270fba970e219a8087a5000000"),
BitcoindRPCException);
}
*/

#include <chrono>

using std::chrono::high_resolution_clock;
using std::chrono::time_point;

inline time_point<high_resolution_clock> clock_start()
{
  return high_resolution_clock::now();
}

inline double time_from(const time_point<high_resolution_clock>& s)
{
  return std::chrono::duration_cast<std::chrono::milliseconds>(
             high_resolution_clock::now() - s)
      .count();
}

TEST_CASE("enclave", "[all]")
{
  exch::interrupt::init_signal_handler();

  // try to create an enclave
  if (0 != initialize_enclave(&eid)) {
    cerr << "failed to init enclave" << endl;
    exit(-1);
  }

  sgx_status_t st;
  int ret = 0;

  for (int n : {100, 200, 300, 400, 500, 600, 1000, 2000, 5000}) {
    auto time_start = clock_start();
    st = sign_n_times(eid, n);
    REQUIRE(st == SGX_SUCCESS);
    std::printf("signing %d times takes %f ms\n", n, time_from(time_start));
  }

  // destroy the enclave last
  sgx_destroy_enclave(eid);
}
