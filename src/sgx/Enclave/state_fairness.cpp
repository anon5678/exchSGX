#include "state.h"
#include "bitcoin/primitives/transaction.h"
#include "bitcoin_helpers.h"

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
int onMessageFromFairnessLeader(const unsigned char *msg, size_t size, unsigned char *tx1_id, unsigned char *tx1_cancel_id) {
  try {
    State &s = State::getInstance();
    s.getProtocolFollower()->receiveFromLeader(msg, size, tx1_id, tx1_cancel_id);
    return 0;
  }
  CATCH_STD_AND_ALL
}

// ecall
int onAckFromFairnessFollower(const unsigned char *_ack, size_t size, unsigned char *tx1_id, unsigned char *tx1_cancel_id) {
  try {
    State &s = State::getInstance();
    s.getProtocolLeader()->receiveAck(_ack, size, tx1_id, tx1_cancel_id);
    return 0;
  }
  CATCH_STD_AND_ALL
}

int onTxOneInMempool(const unsigned char *tx1, size_t size) {
    CMutableTransaction tx;
    if (!DecodeHexTx(tx, string(reinterpret_cast<char const*>(tx1), size), true)) {
        return 0;
    }
    CTransaction Tx(tx);
    //LL_DEBUG("%s", Tx.ToString().c_str());

    try {
        State &s = State::getInstance();
        s.getCurrentProtocol()->foundTxOneInMempool(Tx.GetHash());
        return 0;
    }
    CATCH_STD_AND_ALL
}


// ecall
int afterTimeout() {
    try {
        State &s = State::getInstance();
        s.getCurrentProtocol()->notFoundTxOne();
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

