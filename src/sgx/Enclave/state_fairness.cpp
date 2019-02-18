#include "bitcoin/primitives/transaction.h"
#include "bitcoin_helpers.h"
#include "state.h"

using namespace exch::enclave;
using namespace exch::enclave::fairness;

// TODO: hardcode keys
unsigned char PUBKEYS[3][crypto_box_PUBLICKEYBYTES] = {
    {137, 138, 235, 153, 151, 142, 95, 157, 201, 138, 179,
     104, 198, 112, 171, 246, 72,  71, 68,  157, 129, 134,
     225, 83,  236, 176, 44,  241, 19, 53,  177, 13},
    {203, 115, 206, 68,  124, 102, 206, 178, 42,  54, 9,
     108, 127, 66,  101, 214, 150, 238, 150, 26,  33, 198,
     57,  165, 107, 160, 77,  173, 105, 250, 130, 63},
    {119, 179, 216, 167, 220, 75,  220, 251, 215, 22,  233,
     84,  72,  223, 227, 92,  45,  237, 166, 243, 199, 26,
     56,  163, 31,  210, 225, 133, 101, 190, 163, 10}};
unsigned char SECKEYS[3][crypto_box_SECRETKEYBYTES] = {
    {245, 33,  49,  72,  229, 18,  128, 141, 234, 154, 123,
     190, 121, 108, 203, 228, 107, 233, 36,  65,  137, 209,
     150, 187, 125, 6,   66,  230, 24,  40,  207, 211},
    {131, 115, 213, 174, 165, 215, 33,  46,  99,  119, 109,
     222, 231, 208, 244, 126, 37,  154, 175, 187, 147, 1,
     176, 171, 209, 110, 145, 207, 175, 76,  128, 225},
    {71,  158, 157, 44,  234, 36, 59,  237, 180, 214, 59,
     12,  17,  171, 56,  184, 72, 73,  184, 8,   82,  209,
     212, 191, 122, 103, 249, 49, 168, 113, 196, 36}};

// ecall
int setLeader(const char *hostname, uint16_t port, const uint8_t *pubkey)
{
  ECALL_WRAPPER_RET(State &s = State::getInstance(); s.setLeader(Peer(
      hostname,
      port,
      string((const char *)PUBKEYS[port - 1233], crypto_box_PUBLICKEYBYTES)));)
}

// ecall
int addFairnessFollower(const char *addr, uint16_t port, const uint8_t *pubkey)
{
  ECALL_WRAPPER_RET(State &s = State::getInstance(); s.addPeer(Peer(
      addr,
      port,
      string((const char *)PUBKEYS[port - 1233], crypto_box_PUBLICKEYBYTES)));)
}

// ecall
int removeFairnessFollower(const char *addr, uint16_t port)
{
  ECALL_WRAPPER_RET(LL_CRITICAL("adding peer %s:%d", addr, port);
                    State &s = State::getInstance();
                    s.removePeer(addr, port);)
}

int setSelf(
    int is_leader, const char *hostname, uint16_t port, const uint8_t *pubkey)
{
  ECALL_WRAPPER_RET(State &s = State::getInstance(); s.setSelf(
      (bool)is_leader,
      Peer(
          hostname,
          port,
          string((const char *)PUBKEYS[port - 1233], crypto_box_PUBLICKEYBYTES),
          string(
              (const char *)SECKEYS[port - 1233], crypto_box_SECRETKEYBYTES)));)
}

// ecall
int onMessageFromFairnessLeader(
    const unsigned char *msg,
    size_t size,
    unsigned char *tx1_id,
    unsigned char *tx1_cancel_id)
{
  try {
    State &s = State::getInstance();
    s.getProtocolFollower()->receiveFromLeader(
        msg, size, tx1_id, tx1_cancel_id);
    return 0;
  }
  CATCH_STD_AND_ALL
}

// ecall
int onAckFromFairnessFollower(
    const unsigned char *_ack,
    size_t size,
    unsigned char *tx1_id,
    unsigned char *tx1_cancel_id)
{
  try {
    State &s = State::getInstance();
    s.getProtocolLeader()->receiveAck(_ack, size, tx1_id, tx1_cancel_id);
    return 0;
  }
  CATCH_STD_AND_ALL
}

int onTxOneInMempool(const unsigned char *tx1, size_t size)
{
  CMutableTransaction tx;
  if (!DecodeHexTx(
          tx, string(reinterpret_cast<char const *>(tx1), size), true)) {
    return 0;
  }
  CTransaction Tx(tx);
  // LL_DEBUG("%s", Tx.ToString().c_str());

  try {
    State &s = State::getInstance();
    s.getCurrentProtocol()->foundTxOneInMempool(Tx.GetHash());
    return 0;
  }
  CATCH_STD_AND_ALL
}

// ecall
int afterTimeout()
{
  try {
    State &s = State::getInstance();
    s.getCurrentProtocol()->notFoundTxOne();
    return 0;
  }
  CATCH_STD_AND_ALL
}

// ecall
int onTxOneConfirmation(const merkle_proof_t *merkle_proof)
{
  try {
    State &s = State::getInstance();
    s.getCurrentProtocol()->txOneConfirmed(merkle_proof);
    return 0;
  }
  CATCH_STD_AND_ALL
}
