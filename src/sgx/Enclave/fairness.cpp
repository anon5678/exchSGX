#include "fairness.h"
#include "log.h"
#include "pprint.h"

using namespace exch::enclave::fairness;

Leader::Leader(const tls::TLSCert &leaderCert, const PeerList &peers, Message &&msg) : msg(std::move(msg)) {
  // create tls connections for all peers
  for (auto p : peers) {
    this->peers.emplace_back(leaderCert, p.hostname, p.port);
  }
}

void Leader::disseminate() throw (CannotDisseminate){
  try {
    for (auto p : this->peers) {
      p.connect();
      p.send(msg.serialize());
    }

    for (auto p: this->peers) {
      bytes reply;
      p.receive(reply);
      p.close();
      hexdump("received: ", reply.data(), reply.size());
    }
  }
  catch (const std::exception& e){
    LL_CRITICAL("%s", e.what());
    throw CannotDisseminate();
  }
}

void Leader::trySettleOnBothBlockchain() {
}

Follower::Follower(
    const PeerInfo& leader, const tls::TLSCert& cert) :serverTlsConn(cert.getCert(), cert.getSkPtr()) {
}

void Follower::handle(long int thread_id, thread_info_t *thread_info) {
  this->serverTlsConn.handle(thread_id, thread_info);
}
