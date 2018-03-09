#include "state.h"

using namespace exch::enclave;

bool State::addPeer(const fairness::PeerInfo &peer) {
  auto r = this->fairnessPeers.insert(peer);
  return r.second;
}

bool State::removePeer(const fairness::PeerInfo &peer) {
  auto r = this->fairnessPeers.erase(peer);
  return r == 1;
}

void onMessageFromFairnessLeader() {}
void onAckFromFairnessFollower() {}

