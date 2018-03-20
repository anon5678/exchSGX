#include "state.h"

using namespace exch::enclave;

BlockFIFO<1000> state::blockFIFO;
BalanceBook state::balanceBook;

// SSL servers & clients
TLSClient* state::tlsClient;

bool State::addPeer(const securechannel::Peer &peer) {
  auto r = fairnessPeers.insert(peer);
  return r.second;
}

void State::removePeer(const string &hostname, uint16_t port) {
  auto it = fairnessPeers.begin();
  for (it = fairnessPeers.begin(); it != fairnessPeers.end(); it++) {
    if (it->getHostname() == hostname && it->getPort() == port)
      break;
  }
  fairnessPeers.erase(it);
}

void State::setLeader(const securechannel::Peer &peer) {
  currentLeader = peer;
}

void State::setSelf(bool is_leader, const securechannel::Peer &self) {
  this->isLeader = is_leader;
  this->self = self;
}
