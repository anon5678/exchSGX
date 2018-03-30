#include "fairness.h"
#include "state.h"

using namespace exch::enclave::fairness;
using namespace std;

Leader::Leader(const Peer &me, const vector<Peer> &peers, Message &msg)
    : me(me), msg(move(msg)), peers(peers), peers_ack(peers.size(), false) {
}

void Leader::disseminate() throw(CannotDisseminate) {
  try {
    for (const auto &peer : peers) {
      Box cipher = me.createBoxToPeer(peer, msg.serialize());
      LL_NOTICE("sending %d bytes to %s:%d", cipher.size(), peer.getHostname(), peer.getPort());

      int ret;
      auto st = sendMessagesToFairnessFollower(
          &ret,
          peer.getHostname().c_str(),
          peer.getPort(),
          (const unsigned char *) msg.serialize().data(),
          msg.serialize().size());

      // mark follower as invalid if sending fails
      if (st != SGX_SUCCESS || ret != 0) {
        LL_CRITICAL("cannot send msg to %s", peer.toString().c_str());
        /*
        auto index = distance(peers.begin(), find(peers.begin(), peers.end(), peer));
        if (index < peers.size()) {
          // mark this leader as invalid
          peers_ack[index] = false;
        } else {
          throw runtime_error("cannot find peer in peer list");
        }
        */
      }
    }
  }
  catch (const std::exception &e) {
    LL_CRITICAL("%s", e.what());
    throw CannotDisseminate();
  }
}

void Leader::receiveAck(const string &hostname, uint16_t port) {
  Peer peer(hostname, port, string(32, 0xcc));
  long index = distance(peers.begin(), find(peers.begin(), peers.end(), peer));
  if (index < peers.size()) {
    // mark this leader as invalid
    peers_ack[index] = true;
    LL_NOTICE("received ack from %s", peers[index].toString().c_str());
  } else {
    throw runtime_error("cannot find peer in peer list");
  }

  // decide if trigger the next step
  if (all_of(peers_ack.begin(), peers_ack.end(), [](bool x) { return x; })) {
    LL_NOTICE("received ack from all backup. Now proceed to the next step.");
    // TODO: next step

    this->sendTransaction1();

    LL_NOTICE("tx_1 committed");
  }
}

void Leader::sendTransaction1() {
  // TODO: tx hash can be obtained from the first message
  const string tx_one_id = "288bcaaa05389922d5da1ee0e6d2d08e72770754e0c830adba50e0daa95efd48";
  const string tx_one_cancel_id = "288bcaaa05389922d5da1ee0e6d2d08e72770754e0c830adba50e0daa95efd48";

  // TODO: a fake tx
  bytes tx_one {1,2,3,4};

  LL_NOTICE("sending %s to bitcoin", tx_one_id.c_str());

  int ret;
  auto st = commitTxOne(&ret,tx_one_id.c_str(), tx_one_cancel_id.c_str(), tx_one.data(), tx_one.size());
  if (st != SGX_SUCCESS || ret != 0) {
    throw invalid_argument("cannot send tx1 to blockchain");
  }
}

void Leader::sendTransaction2() {
  LL_NOTICE("sending tx2 to Ethereum blockchain");
}

Follower::Follower(const Peer &me, const Peer &leader)
    : me(me), leader(leader) {
}

