#include "state.h"

using namespace exch::enclave;

fairness::Leader *State::initFairnessProtocol() {
  for (const auto &p : this->fairnessPeers) {
    LL_NOTICE("found peer %s:%d", p.getHostname().c_str(), p.getPort());
  }

  LL_NOTICE("found leader at %s:%d",
            this->currentLeader.getHostname().c_str(),
            this->currentLeader.getPort());

  // TODO: replace this with sealed keys from untrusted world
  string leaderSk;
  string leaderPk = nacl_crypto_box_keypair(&leaderSk);
  Peer leader_info(
      currentLeader.getHostname(),
      currentLeader.getPort(),
      leaderPk,
      leaderSk);

  fairness::Message msg;

  // FIXME: avoid copy
  vector<Peer> peerList;
  copy(this->fairnessPeers.begin(), this->fairnessPeers.end(), back_inserter(peerList));
  auto p = new fairness::Leader(leader_info, peerList, msg);

  // record the current protocol
  this->currentProtocol = p;

  return p;
}

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

using namespace exch::enclave::fairness;

// ecall
int onMessageFromFairnessLeader(const unsigned char *msg, size_t size) {
  try {
    hexdump("receiving msg from leader", msg, size);

    LL_NOTICE("sending ack to leader");

    State &s = State::getInstance();

    AcknowledgeMessage ack{s.getSelf().getHostname(), s.getSelf().getPort()};
    auto ack_msg = ack.serialize();

    // TODO compute an ack message

    int ret;
    auto st = sendAckToFairnessLeader(
        &ret,
        s.getCurrentLeader().getHostname().c_str(),
        s.getCurrentLeader().getPort(),
        (const unsigned char *) ack_msg.data(), ack_msg.size());

    if (st != SGX_SUCCESS || ret != 0) {
      // TODO
      LL_CRITICAL("cannot send ack to the leader");
      return -1;
    }

    return 0;
  }
  CATCH_STD_AND_ALL
}

// ecall
int onAckFromFairnessFollower(const unsigned char *ack, size_t size) {
  try {
    State &s = State::getInstance();
    auto p = s.getCurrentProtocol();
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

    return 0;
  }
  CATCH_STD_AND_ALL
}

// ecall
int onTxOneCommitted() {
  LL_NOTICE("tx1 one been committed");

  return 0;
}

