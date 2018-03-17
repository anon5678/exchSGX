#include "fairness.h"
#include "log.h"
#include "pprint.h"
#include "state.h"

using namespace exch::enclave::fairness;
using namespace std;

Leader::Leader(const Peer& me, const vector<Peer> &peers, Message& msg)
    :me(me), peers(peers), msg(move(msg)) {
}

void Leader::disseminate() throw(CannotDisseminate) {
  try {
    for (const auto& peer : peers) {
      Box cipher = me.createBoxToPeer(peer, msg.serialize());
      LL_NOTICE("sending %d bytes to %s", cipher.size(), peer.getHostname());
    }
  }
  catch (const std::exception &e) {
    LL_CRITICAL("%s", e.what());
    throw CannotDisseminate();
  }
}

void Leader::sendTransaction1() {
  LL_NOTICE("sending tx1");
}

Follower::Follower(const Peer &me, const Peer &leader)
:me(me), leader(leader){
}

