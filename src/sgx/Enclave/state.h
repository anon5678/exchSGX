#ifndef PROJECT_STATE_H
#define PROJECT_STATE_H

#include "blockfifo.hpp"
#include "balancebook.hpp"
#include "tls_server_threaded_t.h"
#include "tls_client.h"
#include "fairness.h"
#include "tls.h"

#include "../common/merkle_data.h"
#include "../common/common.h"

// this file is meant to be used to
// collect the states maintained by a enclave
// and provide interfaces to read / write them.

namespace exch {
namespace enclave {
namespace state {
extern BalanceBook balanceBook;
extern BlockFIFO<1000> blockFIFO;
extern TLSClient *tlsClient;
}
}
}

using namespace exch::enclave;

enum CertType {
  CLIENT_FACING,
  FAIRNESS,
};

class State {
public:
  static State &getInstance() {
    static State instance;
    return instance;
  }

  int setCert(CertType, const unsigned char *, size_t, const char *);
  int getPubkey(
      CertType type,
      unsigned char *o_pubkey,
      size_t cap_pubkey,
      char *o_cert_pem,
      size_t cap_cert_pem
  );

  bool addPeer(const securechannel::Peer &peer);
  void removePeer(const string &hostname, uint16_t port);
  void setLeader(const securechannel::Peer &peer);
  void setSelf(bool is_leader, const securechannel::Peer &self);
  State() {}


private:
  tls::TLSCert fairnessCert;
  tls::TLSCert clientFacingCert;

  /* fairness */
  fairness::Follower *fairnessFollower;
  set<securechannel::Peer> fairnessPeers;
  securechannel::Peer currentLeader;
  fairness::Leader* currentProtocol;
  securechannel::Peer self;
  bool isLeader;

 public:
  // delete copy constructors
  State(const State &) = delete;
  void operator=(const State &) = delete;

  const tls::TLSCert &getFairnessCert() const { return fairnessCert; }
  const tls::TLSCert &getClientCert() const { return this->clientFacingCert; }
  const fairness::PeerList &getPeerList() const { return this->fairnessPeers; }
  const securechannel::Peer& getCurrentLeader() const {return currentLeader; }
  const securechannel::Peer& getSelf() const {return this->self;}

  fairness::Leader * initFairnessProtocol();
  fairness::Leader *getCurrentProtocol() const { return currentProtocol; }

  ~State() {
    delete fairnessFollower;
    delete currentProtocol;
  }
};

#ifdef __cplusplus
extern "C" {
#endif

int merkle_proof_verify(const merkle_proof_t *proof);
int ecall_bitcoin_deposit(const bitcoin_deposit_t *deposit);

int ecall_append_block_to_fifo(const char *blockHeaderHex);
int ecall_get_latest_block_hash(unsigned char *o_buf, size_t cap_obuf);

// SSL server & client
//int fairness_tls_server_init(void);
//void fairness_tls_server_tcp_conn_handler(long int thread_id, ssl_context *thread_info);
//void fairness_tls_server_free(void);

//int client_facing_tls_server_init(void);
//void client_facing_tls_server_tcp_conn_handler(long int thread_id, ssl_context *thread_info);
//void client_facing_tls_server_free(void);

//int ssl_client_init(const char *hostname, unsigned int port);
//int ssl_client_write_test(void);
//void ssl_client_teardown(void);

// key provisioning functions
int rsa_keygen_in_seal(const char *subject_name,
                       unsigned char *o_sealed, size_t cap_sealed,
                       unsigned char *o_pubkey, size_t cap_pubkey,
                       unsigned char *o_csr, size_t cap_csr);

int unseal_secret_and_leak_public_key(const sgx_sealed_data_t *secret,
                                      size_t secret_len, unsigned char *pubkey,
                                      size_t cap_pubkey);

int provision_rsa_id(const unsigned char *secret_key, size_t secret_key_len, const char *cert_pem);

int query_rsa_pubkey(unsigned char *o_pubkey, size_t cap_pubkey, char *o_cert_pem, size_t cap_cert_pem);

#ifdef __cplusplus
}
#endif

#endif //PROJECT_STATE_H
