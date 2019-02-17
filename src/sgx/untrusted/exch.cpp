#include <sgx_urts.h>
#include <atomic>
#include <chrono>
#include <csignal>
#include <fstream>
#include <iostream>
#include <memory>
#include <stdexcept>
#include <thread>

#include <boost/algorithm/hex.hpp>
#include <boost/asio/deadline_timer.hpp>
#include <boost/asio/io_service.hpp>
#include <boost/filesystem.hpp>
#include <boost/program_options.hpp>
#include <boost/thread/thread.hpp>

#include <jsonrpccpp/client/connectors/httpclient.h>
#include <jsonrpccpp/server.h>
#include <jsonrpccpp/server/connectors/httpserver.h>
#include <log4cxx/logger.h>
#include <log4cxx/propertyconfigurator.h>

#include "Enclave_u.h"
#include "Utils.h"
#include "bitcoind-merkleproof.h"
#include "config.h"
#include "external/toml.h"
#include "interrupt.h"
#include "rpc/bitcoind-client.h"
#include "rpc/enclave-server.h"

namespace po = boost::program_options;
namespace fs = boost::filesystem;
namespace aio = boost::asio;

using namespace std;

namespace exch
{
namespace main
{
log4cxx::LoggerPtr logger(log4cxx::Logger::getLogger("exch.cpp"));
}
}  // namespace exch

using exch::main::logger;

extern shared_ptr<aio::io_service> io_service;
extern unique_ptr<boost::asio::deadline_timer> fairnessTimer;
sgx_enclave_id_t eid;

void boost_asio_worker(shared_ptr<aio::io_service> io_service)
{
  LOG4CXX_INFO(logger, "worker thread started");
  while (true) {
    try {
      boost::system::error_code ec;
      io_service->run(ec);
      if (ec) {
        LOG4CXX_ERROR(logger, "Error: " << ec.message());
      }
      // the run() function blocks until io_service is stopped.
      // so break is only hit if io_service is stopped
      break;
    } catch (const std::exception &ex) {
      LOG4CXX_ERROR(logger, "Exception: " << ex.what());
    }
  }
  LOG4CXX_INFO(logger, "worker thread finishes.");
}

void new_block_listener(const string &bitcoind_endpoint)
{
  int num_of_imported_blocks = 0;
  sgx_status_t st;
  int ret;

  LOG4CXX_INFO(logger, "starting the block listener thread")

  Bitcoind bitcoind(bitcoind_endpoint);

  LOG4CXX_INFO(logger, "block listener started")

  while (!exch::interrupt::quit.load()) {
    try {
      auto blockcount = bitcoind.getblockcount();
      // FIXME: this is oversimplified!! it only works until the FIFO is filled.
      // TODO: add an ecall to get the head of the FIFO (i.e., the latest block)
      if (blockcount > num_of_imported_blocks) {
        auto hash = bitcoind.getblockhash(num_of_imported_blocks);
        auto header = bitcoind.getblockheader(hash);

        st = ecall_append_block_to_fifo(eid, &ret, header.c_str());

        if (SGX_SUCCESS != st || ret != 0) {
          if (SGX_SUCCESS != st) {
            print_error_message(st);
          }
          throw std::runtime_error(
              "can't append block to FIFO: return code " + std::to_string(ret));
        }
        num_of_imported_blocks++;
      }
    }

    catch (const std::exception &e) {
      LOG4CXX_ERROR(
          logger,
          "can't get block " << num_of_imported_blocks << ". " << e.what());
    }

    std::this_thread::sleep_for(chrono::seconds(1));
  }
}

int main(int argc, const char *argv[])
{
  // initialize logging and stuff
  Config conf(argc, argv);
  log4cxx::PropertyConfigurator::configure(LOGGING_CONF);
  exch::interrupt::init_signal_handler();

  // create the global io_service
  io_service = std::make_shared<aio::io_service>();
  aio::io_service::work io_work(*io_service);

  // try to create an enclave
  if (0 != initialize_enclave(&eid)) {
    cerr << "failed to init enclave" << endl;
    exit(-1);
  }

  sgx_status_t st;
  int ret = 0;

  boost::thread_group worker_threads;
  for (auto i = 0; i < 5; ++i) {
    worker_threads.create_thread(boost::bind(&boost_asio_worker, io_service));
  }

  // create a thread for the block listener
  worker_threads.create_thread(boost::bind(&new_block_listener, "localhost"));

  // try to load sealed secret keys
#if false
  try {
    LOG4CXX_INFO(logger, "launching " << conf.getIdentity());

    fs::path identity_dir(conf.getIdentity_dir());

    auto sealed_secret_path = (identity_dir / (conf.getIdentity() + ".priv"));
    auto cert_path = (identity_dir / (conf.getIdentity() + ".crt"));

    auto sealed = readBinaryFile(sealed_secret_path.string());
    auto cert = readTextFile(cert_path.string());

    // provision the sealed RSA key. Die if this fails.
    st = provision_rsa_id(eid, &ret, sealed.data(), sealed.size(), cert.c_str());
    if (st != SGX_SUCCESS || ret != 0) {
      cerr << "cannot provision rsa id. ret=" << ret << endl;
      exit(-1);
    }

    // ask enclave for the public key corresponding to the provisioned secret key
    unsigned char pubkey[1024];
    char cert_pem[2048];
    st = query_rsa_pubkey(eid, &ret, pubkey, sizeof pubkey, cert_pem, sizeof cert_pem);
    if (st != SGX_SUCCESS || ret != 0) {
      cerr << "error in provisioning the id" << ret << endl;
      exit(-1);
    }

    LOG4CXX_INFO(logger, "RSA secret key for " << conf.getIdentity() << " provisioned");
  } catch (const std::exception &e) {
    cerr << "cannot provision rsa id: " << e.what() << endl;
    exit(-1);
  }
#endif

  // register followers and leader
  {
    string hostname;
    uint16_t port;
    parse_addr(conf.getLeaderAddr(), &hostname, &port);

    // TODO: dummy pubkey
    uint8_t pubkey[32] = {2};
    st = setLeader(eid, &ret, hostname.c_str(), port, pubkey);
    LOG4CXX_INFO(logger, port);
    if (st != SGX_SUCCESS || ret != 0) {
      LOG4CXX_FATAL(logger, "cannot set leader");
      exit(-1);
    }

    for (const auto &follower_addr : conf.getFollowerAddrList()) {
      parse_addr(follower_addr, &hostname, &port);

      st = addFairnessFollower(eid, &ret, hostname.c_str(), port, pubkey);
      if (st != SGX_SUCCESS || ret != 0) {
        LOG4CXX_FATAL(logger, "cannot add fairness followers");
        exit(-1);
      }
    }
  }

  string rpc_hostname;
  uint16_t rpc_port = 0;
  if (conf.getIsFairnessLeader()) {
    const string &leader_addr = conf.getLeaderAddr();
    parse_addr(leader_addr, &rpc_hostname, &rpc_port);
  } else {
    /* try to find a usable port from fairness.followers */
    for (const string &follower_addr : conf.getFollowerAddrList()) {
      uint16_t tmp_port = 0;
      parse_addr(follower_addr, &rpc_hostname, &tmp_port);
      jsonrpc::HttpServer server(tmp_port);
      if (server.StartListening()) {
        // if the port is not yet used
        rpc_port = tmp_port;
        server.StopListening();
        break;
      }
    }

    // if none of the client port is available
    if (rpc_port == 0) {
      LOG4CXX_FATAL(logger, "cannot start client rpc");
      exit(-1);
    }
  }

  LOG4CXX_INFO(
      logger, "setting " << rpc_hostname << ":" << rpc_port << " as self id");
  st = setSelf(
      eid,
      &ret,
      conf.getIsFairnessLeader(),
      rpc_hostname.c_str(),
      rpc_port,
      vector<uint8_t>(32, 0x99).data()); /* temp public key */
  if (st != SGX_SUCCESS || ret != 0) {
    LOG4CXX_FATAL(logger, "cannot set self id");
    exit(-1);
  }

  bool RPCSrvRunning = false;
  jsonrpc::HttpServer httpserver(rpc_port, "", "");
  EnclaveRPC enclaveRPC(eid, httpserver);
  if (enclaveRPC.StartListening()) {
    RPCSrvRunning = true;
    LOG4CXX_INFO(
        logger, "RPC server listening at " << rpc_hostname << ":" << rpc_port);
  } else {
    LOG4CXX_INFO(logger, "Cannot start RPC server");
    exit(-1);
  }

  // TODO: test only
  if (conf.getIsFairnessLeader()) {
    simulate_leader(eid, &ret);
  }

  while (!exch::interrupt::quit.load()) {
    this_thread::sleep_for(chrono::seconds(2));
  }

  if (RPCSrvRunning) {
    enclaveRPC.StopListening();
    LOG4CXX_INFO(logger, "RPC server shutdown")
  }

  LOG4CXX_INFO(logger, "stopping io_service");
  io_service->stop();
  if (fairnessTimer) {
    fairnessTimer->cancel();
  }
  worker_threads.join_all();

  // destroy the enclave last
  sgx_destroy_enclave(eid);
}
