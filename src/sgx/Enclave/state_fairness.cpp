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
    State &s = State::getInstance();
    s.getProtocolFollower()->receiveFromLeader(msg, size);
    return 0;
  }
  CATCH_STD_AND_ALL
}

// ecall
int onAckFromFairnessFollower(const unsigned char *_ack, size_t size) {
  try {
    State &s = State::getInstance();
    s.getProtocolLeader()->receiveAck(_ack, size);
    return 0;
  }
  CATCH_STD_AND_ALL
}

// ecall
int afterTimeoutT1() {
    try {
        State &s = State::getInstance();
        s.getProtocolFollower()->checkTxOneInMempool();
        return 0;
    }
    CATCH_STD_AND_ALL
}

int afterTimeoutT2() {
    try {
        State &s = State::getInstance();
        s.getCurrentProtocol()->checkTxOneConfirmation();
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
