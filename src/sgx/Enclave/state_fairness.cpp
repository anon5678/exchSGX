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
    hexdump("receiving msg from leader", msg, size);

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

    fairnessProtocolForFollower("a", "b", 10);

    return 0;
  }
  CATCH_STD_AND_ALL
}

// ecall
int onAckFromFairnessFollower(const unsigned char *ack, size_t size) {
  try {
    State &s = State::getInstance();
    string ack_str((char *) ack, size);

    string err;
    const auto ack_json = json11::Json::parse(ack_str, err);

    if (!err.empty()) {
      LL_CRITICAL("cannot parse ack message: %s", err.c_str());
      return -1;
    }

    auto hostname = ack_json["hostname"].string_value();
    auto port = ack_json["port"].int_value();

    s.getCurrentProtocol()->receiveAck(hostname, port);

    LL_NOTICE("onAckFromFairnessFollower exits");
    return 0;
  }
  CATCH_STD_AND_ALL
}

// ecall
int onTxOneCommitted(const merkle_proof_t* merkle_proof, uint8_t* tx2, size_t cap) {
  LL_NOTICE("tx1 one been committed");

  // TODO verify merkle proof
  merkle_proof_verify(merkle_proof);

  State& s = State::getInstance();

  s.getCurrentProtocol()->sendTransaction2();
  return 0;
}

// ecall
int onTxOneNotCommitted(uint8_t* cancel_tx_one, size_t cap) {
  LL_CRITICAL("tx1 is not committed, to send tx1 cancel");

  return 0;
}
