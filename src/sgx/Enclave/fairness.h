#ifndef PROJECT_FAIRNESS_ENCLAVE_H
#define PROJECT_FAIRNESS_ENCLAVE_H

#include <vector>
#include <set>
#include <cstdint>

#include "tls.h"
#include "tls_client.h"
#include "tls_server_threaded_t.h"

#include "Enclave_t.h"

namespace exch {
namespace enclave {
namespace fairness {

struct CannotDisseminate : public std::exception {
  const char *what() const throw() override {
    return "cannot disseminate fairness messages";
  }
};

class Message {
 public:
  Message() = default;
  ~Message() = default;

  // disable copy
  Message(const Message &) = delete;
  Message &operator=(const Message &) = delete;

  Message(Message &&other) noexcept :
      tx_1(std::move(other.tx_1)),
      tx_1_cancel(std::move(other.tx_1_cancel)),
      tx_2(std::move(other.tx_2)),
      tx_2_cancel(std::move(other.tx_2_cancel)) {}

  Message &operator=(Message &&other) noexcept {
    if (this == &other) {
      return *this;
    }

    tx_1 = std::move(other.tx_1);
    tx_1_cancel = std::move(other.tx_1_cancel);
    tx_2 = std::move(other.tx_2);
    tx_2_cancel = std::move(other.tx_2_cancel);

    return *this;
  }

  bytes serialize() const {
    // TODO: this is just a dummy example
    return bytes {1, 2, 3, 4, 5};
  }

 private:
  std::vector<uint8_t> tx_1;
  std::vector<uint8_t> tx_1_cancel;
  std::vector<uint8_t> tx_2;
  std::vector<uint8_t> tx_2_cancel;
};

struct PeerInfo {
  const char *hostname;
  uint16_t port;
  bool operator<(const PeerInfo &rhs) const {
    return strcmp(hostname, rhs.hostname) == 0 ? port < rhs.port : strcmp(hostname, rhs.hostname) < 0;
  }
};

using PeerList=std::set<PeerInfo>;

class FairnessProtocol {
 public:
  enum Role {
    LEADER,
    FOLLOWER,
  };

  // if a follower does not see TX_1 by TIMEOUT_T1, it broadcasts TX_1_Cancel
  // if a leader (or a follower) sees TX_1 on chain 1, it broadcast TX_2 to chain 2
  // if a follower sees TX_1_Cancel on chain 1, it broadcast TX_2_Cancel to chain 2
  const static int TIMEOUT_T1_SECOND = 3600 * 12;
  const static int N_PEER_SERVERS = 5;
};

class Leader : FairnessProtocol {
 public:
  const static auto role = LEADER;
  // initialize
  Leader(const tls::TLSCert &leaderCert, const PeerList &);

  // send msg to all peers and wait for ACKs
  void disseminate(const Message &msg) throw(CannotDisseminate);

  // send TX_1 to blockchain C_1
  void trySettleOnBothBlockchain();

 private:
  std::vector<TLSClient> peers;
};

class Follower : FairnessProtocol {
 public:
  const static auto role = FOLLOWER;
  // create a TLS server
  Follower(const PeerInfo &leader, const tls::TLSCert& cert);

  // simply send ack
  void receiveFromLeader();

  // broadcast cancellation
  void txOneNotAppear();

  // broadcast TX2
  void txOneConfirmed();

  // broadcast TX2 cancellation
  void txOneCanceled();
};

}
}
} // namespace exch::fairness

#endif //PROJECT_FAIRNESS_H