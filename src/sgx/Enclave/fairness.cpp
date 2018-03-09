#include "fairness.h"
#include "log.h"
#include "pprint.h"
#include "state.h"

using namespace exch::enclave::fairness;

int fairnessProtocol() {
  State& s = State::getInstance();
  Leader leader(s.getFairnessCert(), s.getPeerList());

  Message msg {};
  leader.disseminate(msg);

  return 0;
}

Leader::Leader(const tls::TLSCert &leaderCert, const PeerList &peers) {
  // create tls connections for all peers
  for (auto p : peers) {
    this->peers.emplace_back(leaderCert, p.hostname, p.port);
  }
}

void Leader::disseminate(const Message &msg) throw(CannotDisseminate) {
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
  catch (const std::exception &e) {
    LL_CRITICAL("%s", e.what());
    throw CannotDisseminate();
  }
}

void Leader::trySettleOnBothBlockchain() {
}

Follower::Follower(const PeerInfo &leader, const tls::TLSCert &cert) {
}

