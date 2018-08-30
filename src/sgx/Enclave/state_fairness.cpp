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

int onTxOneInMempool(const unsigned char *tx1, size_t size) {
    //TODO: transform tx1 to bytes
    bytes tx_1;

    try {
        State &s = State::getInstance();
        s.getCurrentProtocol()->foundTxOneInMempool(tx_1);
        return 0;
    }
    CATCH_STD_AND_ALL
}


// ecall
int afterTimeout() {
    try {
        State &s = State::getInstance();
        s.getCurrentProtocol()->notFoundTxOneInMempool();
        return 0;
    }
    CATCH_STD_AND_ALL
}

// ecall
int onTxOneConfirmation(const merkle_proof_t *merkle_proof) {
  try {
      State &s = State::getInstance();
      s.getCurrentProtocol()->txOneConfirmed(merkle_proof);
      return 0;
  }
  CATCH_STD_AND_ALL
}

