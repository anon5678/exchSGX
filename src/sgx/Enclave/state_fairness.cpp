#include "state.h"

using namespace exch::enclave;
using namespace exch::enclave::fairness;

// ecall
int setLeader(const char *hostname, uint16_t port, const uint8_t *pubkey) {
  ECALL_WRAPPER_RET(
      State &s = State::getInstance();
      s.setLeader(Peer(hostname, port, string((const char *) pubkey, crypto_box_PUBLICKEYBYTES)));
  )
}

// ecall
int addFairnessFollower(const char *addr, uint16_t port, const uint8_t *pubkey) {
  ECALL_WRAPPER_RET(
      State &s = State::getInstance();
      s.addPeer(Peer(addr, port, string((const char *) pubkey, crypto_box_PUBLICKEYBYTES)));
  )
}

// ecall
int removeFairnessFollower(const char *addr, uint16_t port) {
  ECALL_WRAPPER_RET(
      LL_CRITICAL("adding peer %s:%d", addr, port);
      State &s = State::getInstance();
      s.removePeer(addr, port);
  )
}

int setSelf(int is_leader, const char *hostname, uint16_t port, const uint8_t *pubkey) {
  ECALL_WRAPPER_RET(
      State &s = State::getInstance();
      s.setSelf((bool) is_leader, Peer(hostname, port, string((const char *) pubkey, crypto_box_PUBLICKEYBYTES)));
  )
}

// ecall
int onMessageFromFairnessLeader(const unsigned char *msg, size_t size) {
  try {
    SettlementPkg pkg = SettlementPkg::deserialize(string((char *) msg, size));

    LL_NOTICE("sending ack to leader");
    State &s = State::getInstance();

    // TODO compute an actual ack message
    AcknowledgeMessage ack{s.getSelf().getHostname(), s.getSelf().getPort()};
    auto ack_msg = ack.serialize();

    int ret;
    auto st = sendAckToFairnessLeader(
        &ret,
        s.getCurrentLeader().getHostname().c_str(),
        s.getCurrentLeader().getPort(),
        (const unsigned char *) ack_msg.data(), ack_msg.size());

    if (st != SGX_SUCCESS || ret != 0) {
      LL_CRITICAL("cannot send ack to the leader");
      return -1;
    }

    //TODO sleep for a certain TIMEOUT
    
    //send tx_1_cancel and it gets accepted if tx_1 is not confirmed yet
    st = sendTxToBlockchain();
    if (st != SGX_SUCCESS) {
        LL_CRITICAL("fails to send tx_1_cancel to Bitcoin.");
    }

    st = fairnessTimerHandler(
        &ret, 
        pkg.tx_1_id_hex.c_str(),
        pkg.tx_1_cancel_id_hex.c_str());

    if (st != SGX_SUCCESS || ret != 0) {
      LL_CRITICAL("fairnessProtocolForFollower fails.");
      return -1;
    }

    return 0;
  }
  CATCH_STD_AND_ALL
}

// ecall
int onAckFromFairnessFollower(const unsigned char *_ack, size_t size) {
  try {
    State &s = State::getInstance();
    AcknowledgeMessage ack = AcknowledgeMessage::deserailize(string((char *) _ack, size));
    s.getCurrentProtocol()->receiveAck(ack);
    return 0;
  }
  CATCH_STD_AND_ALL
}

// ecall
int onTxOneCommitted(const merkle_proof_t *merkle_proof) {
  LL_NOTICE("tx1 one been committed");

  // TODO verify merkle proof
  merkle_proof_verify(merkle_proof);

  State &s = State::getInstance();

  s.getCurrentProtocol()->txOneConfirmed();
  return 0;
}

// ecall
int onTxOneNotCommitted(const merkle_proof_t *merkle_proof) {
  LL_CRITICAL("tx1 is not committed, to send tx1 cancel");

  // TODO verify merkle proof
  merkle_proof_verify(merkle_proof);

  State &s = State::getInstance();

  s.getCurrentProtocol()->txOneCanceled();
  return 0;
}
