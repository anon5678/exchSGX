#include <log4cxx/logger.h>
#include <log4cxx/propertyconfigurator.h>

#include "Enclave_u.h"
#include "Utils.h"
#include "config.h"
#include "interrupt.h"

using namespace std;

namespace exch
{
namespace main
{
log4cxx::LoggerPtr logger(log4cxx::Logger::getLogger("exch.cpp"));
}
}  // namespace exch

using exch::main::logger;

sgx_enclave_id_t eid;

int main(int argc, const char *argv[])
{
  Config conf(argc, argv);
  log4cxx::PropertyConfigurator::configure(LOGGING_CONF);
  exch::interrupt::init_signal_handler();

  // try to create an enclave
  if (0 != initialize_enclave(&eid)) {
    cerr << "failed to init enclave" << endl;
    exit(-1);
  }

  sgx_status_t st;
  int ret = 0;

  // call the function at Enclave/enclave_test.cpp:55
  st = enclaveTest(eid, &ret);
  if (st != SGX_SUCCESS) {
    LOG4CXX_ERROR(logger, "ecall failed with return value " << st);
  }

  // destroy the enclave last
  sgx_destroy_enclave(eid);
}
