#include "state.h"

#include "Enclave_t.h"

using namespace exch::enclave;

bool State::addPeer(const securechannel::Peer &peer) {
  auto r = fairnessPeers.insert(peer);
  return r.second;
}

bool State::removePeer(const securechannel::Peer &peer) {
  auto r = fairnessPeers.erase(peer);
  return r == 1;
}

void onMessageFromFairnessLeader(const unsigned char *msg, size_t size) {
  LL_NOTICE("receiving msg from leader");

  string ack = "ack";

  // TODO: reading port from a config file
  sendAckToFairnessLeader("localhost", 1235, (const unsigned char*) ack.data(), ack.size());
}
void onAckFromFairnessFollower(const unsigned char *ack, size_t size) {
  hexdump("receiving ack: ", ack, size);
}

