#include "fairness.h"
#include "state.h"

using namespace exch::enclave::fairness;
using namespace std;

constexpr const char *SettlementPkg::TX_ONE_ID;
constexpr const char *SettlementPkg::TX_ONE_CANCEL_ID;
constexpr const char *SettlementPkg::TX_ONE;
constexpr const char *SettlementPkg::TX_TWO;
constexpr const char *SettlementPkg::TX_ONE_CANCEL;
constexpr const char *SettlementPkg::TX_TWO_CANCEL;

void FairnessProtocol::txOneConfirmed(const merkle_proof_t *proof) {
  if (stage != SENDTXONE) {
      LL_NOTICE("not on the stage to check tx1 status");
      return;
  }

  int ret;
  int st;
  if (true) {//TODO: merkle_proof_verify(proof)) {
      if (true) { //TODO: tx1 confirmed
          LL_NOTICE("sending tx2 to blockchain");
          st = sendTxToBlockchain(&ret);
      } else { //tx1_cancel confirmed
          LL_NOTICE("sending tx2_cancel to blockchain");
          st = sendTxToBlockchain(&ret);
      }
      
      if (st != SGX_SUCCESS || ret != 0) {
          LL_CRITICAL("cannot send tx2/tx2_cancel to blockchain");
          return;
      }

      stage = SENDTXTWO;
      LL_NOTICE("fairness protocol finishes");
  } else {
      LL_NOTICE("merkle proof verification fails");
  }

}

Leader::Leader(const Peer &me, const vector<Peer> &peers)
    : FairnessProtocol(me), peers(peers), peers_ack(peers.size(), false) {
    stage = INIT;
}

void Leader::setMessage(SettlementPkg &&message) {
    msg = move(message);
}


void Leader::disseminate() noexcept(false) {
  if (stage != INIT) {
      LL_NOTICE("not on the stage to disseminate");
      return;
  }

  try {
    for (const auto &peer : peers) {
      Box cipher = me.createBoxToPeer(peer, msg.serialize());
      LL_NOTICE("sending %d bytes to %s:%d", cipher.size(), peer.getHostname().c_str(), peer.getPort());

      int ret;
      auto st = sendMessagesToFairnessFollower(
          &ret,
          peer.getHostname().c_str(),
          peer.getPort(),
          // TODO: send the actual box
          (const unsigned char *) msg.serialize().data(),
          msg.serialize().size());

      // mark follower as invalid if sending fails
      if (st != SGX_SUCCESS || ret != 0) {
        LL_CRITICAL("cannot send msg to %s", peer.toString().c_str());
        auto index = distance(peers.begin(), find(peers.begin(), peers.end(), peer));
        if (index < peers.size()) {
          // mark this leader as invalid
          peers_ack[index] = false;
        } else {
          throw runtime_error("cannot find peer in peer list");
        }
      }
    }
    stage = DISSEMINATE;
  }
  catch (const std::exception &e) {
    LL_CRITICAL("%s", e.what());
    throw CannotDisseminate();
  }
}

void Leader::receiveAck(const unsigned char *_ack, size_t size) {
  if (stage != DISSEMINATE) {
      LL_NOTICE("not on the stage to wait for acks");
      return;
  }

  //TODO: check signature of ack
  AcknowledgeMessage ack = AcknowledgeMessage::deserailize(string((char *) _ack, size));

  Peer peer(ack.hostname, ack.port, string(32, 0xcc));
  long index = distance(peers.begin(), find(peers.begin(), peers.end(), peer));
  if (index < peers.size()) {
    // mark this leader as valid
    peers_ack[index] = true;
    LL_NOTICE("received ack from %s", peers[index].toString().c_str());
  } else {
    throw runtime_error("cannot find peer in peer list");
  }

  // decide if trigger the next step
  if (all_of(peers_ack.begin(), peers_ack.end(), [](bool x) { return x; })) {
    LL_NOTICE("received ack from all backup. Now proceed to the next step.");

    LL_NOTICE("sending %s (%d bytes) to bitcoin", msg.tx_1_id_hex.c_str(), msg.tx_1.size());

    int ret;
    auto st = sendTxToBlockchain(&ret);

    if (st != SGX_SUCCESS || ret != 0) {
      LL_CRITICAL("cannot send tx1 to blockchain");
    }

    start_time.getTime();
    start_time.period = TIMEOUT_T1_SECOND;

    stage = RECEIVEACK;
    LL_NOTICE("currently on stage RECEIVEACK");
  }
}

Follower::Follower(const Peer &me, const Peer &leader)
    : FairnessProtocol(me), leader(leader) {
    stage = INIT;
}

void Follower::receiveFromLeader(const unsigned char *msg, size_t size) {
    if (stage != INIT) {
        LL_NOTICE("not on the stage to receive message from leader");
        return;
    }

    //TODO: decrypt message from leader
    SettlementPkg pkg = SettlementPkg::deserialize(string((char *) msg, size));

    LL_NOTICE("sending ack to leader");
    // TODO compute an actual ack message
    AcknowledgeMessage ack{me.getHostname(), me.getPort()};
    auto ack_msg = ack.serialize();

    int ret;
    auto st = sendAckToFairnessLeader(
        &ret,
        leader.getHostname().c_str(),
        leader.getPort(),
        (const unsigned char *) ack_msg.data(), ack_msg.size());

    if (st != SGX_SUCCESS || ret != 0) {
      LL_CRITICAL("cannot send ack to the leader");
      return;
    }

    start_time.getTime();
    start_time.period = TIMEOUT_T1_SECOND;

    stage = SENDACK;
    LL_NOTICE("currently on stage SENDACK");
}

void FairnessProtocol::foundTxOneInMempool(const bytes &txOneInMempool) {
    if (stage != SENDACK && stage != RECEIVEACK) {
        LL_NOTICE("not on the stage to accept tx1 found in mempool");
        return;
    }

    if (true) {//txOneInMempool == msg.tx_1) {
        LL_NOTICE("found tx1 in mempool");
        stage = SENDTXONE;
    }
}

void FairnessProtocol::notFoundTxOneInMempool() {
    if (stage != SENDACK && stage != RECEIVEACK) {
        LL_NOTICE("not on the stage to check tx1 in mempool");
        return;
    }

    if (!start_time.passTime()) {
        LL_NOTICE("not time to check tx1 in mempool");
        return;
    }

    LL_NOTICE("not found tx1 in mempool after timeout, start to send tx1_cancel");

    int ret = 0;
    auto st = sendTxToBlockchain(
            &ret);
    if (st != SGX_SUCCESS || ret != 0) {
        LL_CRITICAL("cannot send tx1_cancel to the blockchain");
        return;
    }

    stage = SENDTXONE;
}

