#include "fairness.h"
#include "../common/utils.h"
#include "bitcoin/utilstrencodings.h"
#include "securechannel.h"
#include "state.h"

using namespace exch::enclave::fairness;
using namespace std;

constexpr const char *SettlementPkg::TX_ONE_ID;
constexpr const char *SettlementPkg::TX_ONE_CANCEL_ID;
constexpr const char *SettlementPkg::TX_ONE;
constexpr const char *SettlementPkg::TX_TWO;
constexpr const char *SettlementPkg::TX_ONE_CANCEL;
constexpr const char *SettlementPkg::TX_TWO_CANCEL;


//TODO: return execution state to the untrusted part
void FairnessProtocol::txOneConfirmed(const unsigned char* header_hash, size_t size, const merkle_proof_t *proof)
{
  sgx_thread_mutex_lock(&state_mutex);
  if (stage != SENDTXONE && stage != SENDTXONECANCEL && stage != SENDACK &&
      stage != RECEIVEACK) {
    LL_NOTICE("not on the stage to check tx1 status");
  } else {
    try {
      int ret;
      int st;

      if (merkle_proof_verify(header_hash, size, proof) == 0) {
        LL_NOTICE("merkle proof verified");

        unsigned char *tmp = new unsigned char[33]();
        memcpy(tmp, proof->tx, 32);
        byte_swap(tmp, 32);
        string tx_id = bin2hex(tmp, 32);
        // LL_NOTICE("%s", tx_id.c_str());
        if (tx_id == msg.tx_1_id_hex) {
          LL_NOTICE(
              "tx1 confirmed on the blockchain, sending tx2 to blockchain");
          st = sendTxToBlockchain(&ret);
        } else if (tx_id == msg.tx_1_cancel_id_hex) {
          LL_NOTICE(
              "tx1_cancel confirmed on the blockchain, sending tx2_cancel to "
              "blockchain");
          st = sendTxToBlockchain(&ret);
        }

        if (st != SGX_SUCCESS || ret != 0) {
          LL_CRITICAL("cannot send tx2/tx2_cancel to blockchain");
        } else {
          stage = SENDTXTWO;
          LL_NOTICE("fairness protocol finishes");
        }
      } else {
        LL_NOTICE("merkle proof verification fails");
      }
    } catch (const std::exception &e) {
      LL_CRITICAL("%s", e.what());
    }
  }
  sgx_thread_mutex_unlock(&state_mutex);
}

Leader::Leader(const Peer &me, const vector<Peer> &peers)
    : FairnessProtocol(me), peers(peers), peers_ack(peers.size(), false)
{
  stage = INIT;
}

void Leader::setMessage(SettlementPkg &&message) { msg = move(message); }

void Leader::disseminate() noexcept(false)
{
  sgx_thread_mutex_lock(&state_mutex);
  /* KeyGen
  for (int i = 0; i < 3; ++i) {
      string sk;
      string pk = nacl_crypto_box_keypair(&sk);
      string skk = "";
      string pkk = "";
      for (int j = sk.size() - 1; j >= 0; --j) {
          int tmp = (unsigned char)sk[j];
          if (tmp == 0) {
              skk = '0' + skk;
          }
          while (tmp) {
              skk = (char)((tmp % 10) + '0') + skk;
              tmp = tmp / 10;
          }
          if (j != 0) skk = ',' + skk;
      }
      for (int j = pk.size() - 1; j >= 0; --j) {
          int tmp = (unsigned char)pk[j];
          if (tmp == 0) {
              pkk = '0' + pkk;
          }
          while (tmp) {
              pkk = (char)((tmp % 10) + '0') + pkk;
              tmp = tmp / 10;
          }
          if (j != 0) pkk = ',' + pkk;
      }
      LL_DEBUG("%d: sk: (%s), pk: (%s)", i, skk.c_str(), pkk.c_str());
  }
  */
  if (stage != INIT) {
    LL_NOTICE("not on the stage to disseminate");
  } else {
    try {
      for (const auto &peer : peers) {
        Box cipher = me.createBoxToPeer(peer, msg.serialize());
        LL_NOTICE(
            "sending %d bytes to %s:%d",
            cipher.serialize().size(),
            peer.getHostname().c_str(),
            peer.getPort());

        int ret;
        auto st = sendMessagesToFairnessFollower(
            &ret,
            peer.getHostname().c_str(),
            peer.getPort(),
            (const unsigned char *)cipher.serialize().data(),
            cipher.serialize().size());

        // mark follower as invalid if sending fails
        if (st != SGX_SUCCESS || ret != 0) {
          LL_CRITICAL("cannot send msg to %s", peer.toString().c_str());
          auto index =
              distance(peers.begin(), find(peers.begin(), peers.end(), peer));
          if (index < peers.size()) {
            // mark this leader as invalid
            peers_ack[index] = false;
          } else {
            throw runtime_error("cannot find peer in peer list");
          }
        }
      }
      stage = DISSEMINATE;
    } catch (const std::exception &e) {
      LL_CRITICAL("%s", e.what());
    }
  }
  sgx_thread_mutex_unlock(&state_mutex);
}

void Leader::receiveAck(
    const unsigned char *_ack,
    size_t size,
    unsigned char *tx1_id,
    unsigned char *tx1_cancel_id)
{
  sgx_thread_mutex_lock(&state_mutex);
  if (stage != DISSEMINATE) {
    LL_NOTICE("not on the stage to wait for acks");
  } else {
    try {
      AckPackage ackp = AckPackage::deserialize(string((char *)_ack, size));
      long index;
      for (index = 0; index < peers.size(); ++index) {
        if (peers[index].getHostname() == ackp.getHostname() &&
            peers[index].getPort() == ackp.getPort()) {
          break;
        }
      }

      if (index < peers.size()) {
        string tmp =
            me.openBoxFromPeer(Box::deserialize(ackp.cipher), peers[index]);
        AcknowledgeMessage ack = AcknowledgeMessage::deserialize(tmp);
        if (ack.getHostname() != ackp.getHostname() ||
            ack.getPort() != ackp.getPort() ||
            ack.getTx1_id() != msg.tx_1_id_hex) {
          throw runtime_error("invalid MAC for ACK message");
        } else {
          // mark this leader as valid
          peers_ack[index] = true;
          LL_NOTICE("received ack from %s", peers[index].toString().c_str());
        }
      } else {
        throw runtime_error("cannot find peer in peer list");
      }

      // decide if trigger the next step
      if (all_of(
              peers_ack.begin(), peers_ack.end(), [](bool x) { return x; })) {
        LL_NOTICE(
            "received ack from all backup. Now proceed to the next step.");

        LL_NOTICE(
            "sending %s (%d bytes) to bitcoin",
            msg.tx_1_id_hex.c_str(),
            msg.tx_1.size());

        int ret;
        auto st = sendTxToBlockchain(&ret);

        if (st != SGX_SUCCESS || ret != 0) {
          LL_CRITICAL("cannot send tx1 to blockchain");
        }

        timer1.getTime();
        timer1.period = TIMEOUT_T1_SECOND;
        timer2.getTime();
        timer2.period = TIMEOUT_T2_SECOND;

        this->msg.tx_1_id_hex.copy((char *)tx1_id, 64);
        this->msg.tx_1_cancel_id_hex.copy((char *)tx1_cancel_id, 64);

        stage = RECEIVEACK;
        LL_NOTICE("currently on stage RECEIVEACK");
      }
    } catch (const std::exception &e) {
      LL_CRITICAL("%s", e.what());
    }
  }
  sgx_thread_mutex_unlock(&state_mutex);
}

Follower::Follower(const Peer &me, const Peer &leader)
    : FairnessProtocol(me), leader(leader)
{
  stage = INIT;
}

void Follower::receiveFromLeader(
    const unsigned char *msg,
    size_t size,
    unsigned char *tx1_id,
    unsigned char *tx1_cancel_id)
{
  sgx_thread_mutex_lock(&state_mutex);
  if (stage != INIT) {
    LL_NOTICE("not on the stage to receive message from leader");
  } else {
    try {
      Box cipher = Box::deserialize(string((char *)msg, size));
      string tmp = me.openBoxFromPeer(cipher, leader);

      this->msg = SettlementPkg::deserialize(tmp);
      this->msg.tx_1_id_hex.copy((char *)tx1_id, 64);
      this->msg.tx_1_cancel_id_hex.copy((char *)tx1_cancel_id, 64);

      LL_NOTICE("sending ack to leader");
      AcknowledgeMessage ack{
          me.getHostname(), me.getPort(), this->msg.tx_1_id_hex};
      auto ack_msg = me.createBoxToPeer(leader, ack.serialize()).serialize();
      AckPackage ackp = AckPackage(me.getHostname(), me.getPort(), ack_msg);

      int ret;
      auto st = sendAckToFairnessLeader(
          &ret,
          leader.getHostname().c_str(),
          leader.getPort(),
          (const unsigned char *)ackp.serialize().data(),
          ackp.serialize().size());

      if (st != SGX_SUCCESS || ret != 0) {
        LL_CRITICAL("cannot send ack to the leader");
      } else {
        timer1.getTime();
        timer1.period = TIMEOUT_T1_SECOND;
        timer2.getTime();
        timer2.period = TIMEOUT_T2_SECOND;

        stage = SENDACK;
        LL_NOTICE("currently on stage SENDACK");
      }
    } catch (const std::exception &e) {
      LL_CRITICAL("%s", e.what());
    }
  }
  sgx_thread_mutex_unlock(&state_mutex);
}

void FairnessProtocol::foundTxOneInMempool(const uint256 tx)
{
  sgx_thread_mutex_lock(&state_mutex);
  if (stage != SENDACK && stage != RECEIVEACK) {
    LL_NOTICE("not on the stage to accept tx1 found in mempool");
  } else {
    try {
      unsigned char *tx_tmp = new unsigned char[33];
      hex2bin(tx_tmp, HexStr(tx).c_str());
      byte_swap(tx_tmp, 32);
      LL_DEBUG("tx hex: %s", bin2hex(tx_tmp, 32).c_str());
      if (bin2hex(tx_tmp, 32) == msg.tx_1_id_hex) {
        LL_NOTICE("found tx1 in mempool");
        stage = SENDTXONE;
      }
    } catch (const std::exception &e) {
      LL_CRITICAL("%s", e.what());
    }
  }
  sgx_thread_mutex_unlock(&state_mutex);
}

void FairnessProtocol::notFoundTxOne()
{
  sgx_thread_mutex_lock(&state_mutex);
  if (stage != SENDACK && stage != RECEIVEACK && stage != SENDTXONE) {
    LL_NOTICE("not on the stage to check tx1");
  } else {
    try {
      if (!timer1.passTime()) {
        LL_NOTICE("not time to check tx1 in mempool");
      } else if ((stage == SENDTXONE) && (!timer2.passTime())) {
        LL_NOTICE("not time to check tx1 on blockchain");
      } else {
        LL_NOTICE(
            "not found tx1 in mempool after timeout, start to send tx1_cancel");

        int ret = 0;
        auto st = sendTxToBlockchain(&ret);
        if (st != SGX_SUCCESS || ret != 0) {
          LL_CRITICAL("cannot send tx1_cancel to the blockchain");
        } else {
          stage = SENDTXONECANCEL;
        }
      }
    } catch (const std::exception &e) {
      LL_CRITICAL("%s", e.what());
    }
  }
  sgx_thread_mutex_unlock(&state_mutex);
}
