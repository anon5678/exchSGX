#include "Utils.h"
#include "bitcoind-merkleproof.h"
#include "merkpath/merkpath.h"
#include "rpc/bitcoind-client.h"

#include <algorithm>
#include <fstream>

#include <log4cxx/logger.h>
#include <log4cxx/propertyconfigurator.h>

namespace exch
{
namespace merkleproof
{
log4cxx::LoggerPtr logger(log4cxx::Logger::getLogger("merkleproof"));
}
}  // namespace exch

using exch::merkleproof::logger;

int main(int argc, const char *argv[])
{
  if (argc < 2) {
    cout << "Usage: " << argv[0] << " txid" << endl;
    exit(-1);
  }

  log4cxx::PropertyConfigurator::configure(LOGGING_CONF);

  string txid(argv[1]);

  auto proof = buildTxInclusionProof(txid);

  proof.dumpJSON(cout);

  string filename = txid.substr(0, 6) + ".merkle";
  ofstream out(filename);
  proof.dumpJSON(out);
  out.close();

  LOG4CXX_INFO(logger, "Proof is dumped to " << filename);
  return 0;
}
