#include "state.h"

using namespace exch::enclave;

bool State::addPeer(const securechannel::Peer &peer) {
  auto r = fairnessPeers.insert(peer);
  return r.second;
}

bool State::removePeer(const securechannel::Peer &peer) {
  auto r = fairnessPeers.erase(peer);
  return r == 1;
}

void onMessageFromFairnessLeader() {}
void onAckFromFairnessFollower() {}

