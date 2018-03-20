#include "state.h"

#include "Enclave_t.h"

#include "nacl/tweetnacl.h"

#define ECALL_WRAPPER_NO_RET(expr) \
  try { expr; return 0; }                          \
  catch (const std::exception & e) { LL_CRITICAL("error happened: %s", e.what()); return -1; }\
  catch (...) { LL_CRITICAL("unknown error happened"); return -1; }

using namespace exch::enclave;

bool State::addPeer(const securechannel::Peer &peer) {
  auto r = fairnessPeers.insert(peer);
  return r.second;
}

void State::removePeer(const string &hostname, uint16_t port) {
  auto it = fairnessPeers.begin();
  for (it = fairnessPeers.begin(); it != fairnessPeers.end(); it++) {
    if (it->getHostname() == hostname && it->getPort() == port)
      break;
  }
  fairnessPeers.erase(it);
}

void State::setLeader(const securechannel::Peer &peer) {
  currentLeader = peer;
}

// ecall
int setLeader(const char *hostname, uint16_t port, const uint8_t *pubkey) {
  ECALL_WRAPPER_NO_RET(
      State &s = State::getInstance();
      s.setLeader(Peer(hostname, port, string((const char *) pubkey, crypto_box_PUBLICKEYBYTES)));
  )
}

// ecall
int addFairnessFollower(const char *addr, uint16_t port, const uint8_t *pubkey) {
  ECALL_WRAPPER_NO_RET(
      State &s = State::getInstance();
      s.addPeer(Peer(addr, port, string((const char *) pubkey, crypto_box_PUBLICKEYBYTES)));
  )
}

// ecall
int removeFairnessFollower(const char *addr, uint16_t port) {
  ECALL_WRAPPER_NO_RET(
      LL_CRITICAL("adding peer %s:%d", addr, port);
      State &s = State::getInstance();
      s.removePeer(addr, port);
  )
}

// ecall
int onMessageFromFairnessLeader(const unsigned char *msg, size_t size) {
  ECALL_WRAPPER_NO_RET(
      LL_NOTICE("sending ack to leader");

      State &s = State::getInstance();
      string ack = "ack";

      // TODO: reading port from a config file
      sendAckToFairnessLeader(
          s.getCurrentLeader().getHostname().c_str(),
          s.getCurrentLeader().getPort(),
          (const unsigned char *) ack.data(), ack.size());
  )
}

// ecall
int onAckFromFairnessFollower(const unsigned char *ack, size_t size) {
  ECALL_WRAPPER_NO_RET(
      hexdump("receiving ack: ", ack, size);
  )
}

