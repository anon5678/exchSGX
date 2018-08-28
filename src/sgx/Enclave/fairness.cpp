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

void FairnessProtocol::txOneConfirmed() {
    //TODO: sendTxTwo;
}

void FairnessProtocol::txOneCanceled() {
    //TODO: sendTxTwoCancel;
}

void FairnessProtocol::waitForConfirmation() {
  if (stage != SENDTXONE) {
      LL_NOTICE("not on the stage to check tx1 status");
      return;
  }
  
  if (!start_time.passTime()) {
      LL_NOTICE("not time to check tx1 status");
      return;
  }

  try {
      //TODO: checkTxOneStatus();
  }
  catch (exception e) {
      throw;
  }

  stage = SENDTXTWO;
}

Leader::Leader(const Peer &me, const vector<Peer> &peers) //, SettlementPkg &&msg)
    : me(me), peers(peers), peers_ack(peers.size(), false) { //, msg(move(msg)) {
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

void Leader::receiveAck(const AcknowledgeMessage &ack) {
  if (stage != DISSEMINATE) {
      LL_NOTICE("not on the stage to wait for acks");
      return;
  }

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
    // TODO: next step

    //this->sendTransaction();

    LL_NOTICE("sending %s (%d bytes) to bitcoin", msg.tx_1_id_hex.c_str(), msg.tx_1.size());

    int ret;
    auto st = sendTxToBlockchain(&ret);

    if (st != SGX_SUCCESS || ret != 0) {
      LL_CRITICAL("cannot send tx1 to blockchain");
    }

    start_time.getTime();
    start_time.period = TIMEOUT_T2_SECOND;
 
    stage = SENDTXONE;
    
    /*st = fairnessProtocolForFollower(&ret, 
                                     &msg.tx_1_id_hex.c_str()
                                     &msg.tx_1_cancel_id_hex.c_str(),
                                     0);

    st = fairnessTimerHandler(//&ret,
                              msg.tx_1_id_hex.c_str(),
                              msg.tx_1_cancel_id_hex.c_str());
    if (st != SGX_SUCCESS || ret != 0) {
        LL_CRITICAL("fairnessProtocolForFollower fails.");
    }*/
    
  }
}

Follower::Follower(const Peer &me, const Peer &leader)
    : me(me), leader(leader) {
    stage = INIT;
}

void Follower::receiveFromLeader() {
    if (stage != INIT) {
        LL_NOTICE("not on the stage to receive message from leader");
        return;
    }
    
    //TODO: sendack;

    start_time.getTime();
    start_time.period = TIMEOUT_T1_SECOND;

    stage = SENDACK;
}

void Follower::checkTxOneInMempool() {
    if (stage != SENDACK) {
        LL_NOTICE("not on the stage to receive message from leader");
        return;
    }

    if (!start_time.passTime()) {
        LL_NOTICE("not time to check tx1 in mempool");
        return;
    }

    //TODO: sendtx1cancel;

    start_time.getTime();
    start_time.period = TIMEOUT_T2_SECOND;

    stage = SENDTXONE;
}

