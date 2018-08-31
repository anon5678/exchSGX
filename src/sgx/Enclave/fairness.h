#ifndef PROJECT_FAIRNESS_ENCLAVE_H
#define PROJECT_FAIRNESS_ENCLAVE_H

#include <vector>
#include <set>
#include <map>
#include <cstdint>

#include "securechannel.h"
#include "Enclave_t.h"
#include "json11.hpp"

namespace exch {
namespace enclave {
namespace fairness {

using std::vector;
using namespace exch::enclave::securechannel;

struct CannotDisseminate : public std::exception {
  const char *what() const throw() override {
    return "cannot disseminate fairness messages";
  }
};

struct AcknowledgeMessage {
  string hostname;
  int port;

  static AcknowledgeMessage deserailize(const string &json) noexcept(false) {
    string err;
    const auto ack_json = json11::Json::parse(json, err);

    if (!err.empty()) {
      throw (string("cannot parse ack message: ") + err.c_str());
    }

    auto hostname = ack_json["hostname"].string_value();
    auto port = ack_json["port"].int_value();

    return AcknowledgeMessage{hostname, port};
  }

  string serialize() {
    json11::Json json = json11::Json::object{
        {"hostname", hostname},
        {"port", port}
    };
    return json.dump();
  }

};

struct SettlementPkg {
  string tx_1_id_hex;
  string tx_1_cancel_id_hex;
  bytes tx_1;
  bytes tx_2;
  bytes tx_1_cancel;
  bytes tx_2_cancel;

  static constexpr const char *TX_ONE_ID = "tx_1_id";
  static constexpr const char *TX_ONE_CANCEL_ID = "tx_1_cancel_id";
  static constexpr const char *TX_ONE = "tx_1";
  static constexpr const char *TX_TWO = "tx_2";
  static constexpr const char *TX_ONE_CANCEL = "tx_1_cancel";
  static constexpr const char *TX_TWO_CANCEL = "tx_2_cancel";

  SettlementPkg(const string &tx_1_id, const string &tx_1_cancel_id,
                const bytes &tx_1, const bytes &tx_2,
                const bytes &tx_1_cancel, const bytes &tx_2_cancel)
      : tx_1_id_hex(tx_1_id), tx_1_cancel_id_hex(tx_1_cancel_id),
        tx_1(tx_1), tx_2(tx_2),
        tx_1_cancel(tx_1_cancel), tx_2_cancel(tx_2_cancel) {}

  SettlementPkg() = default;

  ~SettlementPkg() = default;

  // disable copy
  SettlementPkg(const SettlementPkg &) = delete;
  SettlementPkg &operator=(const SettlementPkg &) = delete;

  // define move
  SettlementPkg(SettlementPkg &&other) noexcept :
      tx_1_id_hex(std::move(other.tx_1_id_hex)),
      tx_1_cancel_id_hex(std::move(other.tx_1_cancel_id_hex)),
      tx_1(std::move(other.tx_1)),
      tx_2(std::move(other.tx_2)),
      tx_1_cancel(std::move(other.tx_1_cancel)),
      tx_2_cancel(std::move(other.tx_2_cancel)) {}

  SettlementPkg &operator=(SettlementPkg &&other) noexcept {
    if (this == &other) {
      return *this;
    }

    tx_1_id_hex = std::move(other.tx_1_id_hex);
    tx_1_cancel_id_hex = std::move(other.tx_1_cancel_id_hex);
    tx_1 = std::move(other.tx_1);
    tx_2 = std::move(other.tx_2);
    tx_1_cancel = std::move(other.tx_1_cancel);
    tx_2_cancel = std::move(other.tx_2_cancel);

    return *this;
  }

  string serialize() const {
    json11::Json json = json11::Json::object{
        {TX_ONE_ID, tx_1_id_hex},
        {TX_ONE_CANCEL_ID, tx_1_cancel_id_hex},
        {TX_ONE, tx_1},
        {TX_TWO, tx_2},
        {TX_ONE_CANCEL, tx_1_cancel},
        {TX_TWO_CANCEL, tx_2_cancel}
    };
    return json.dump();
  }

  static bytes jsonArrayToBytes(json11::Json::array arr) {
    bytes bytearray;

    std::transform(
        arr.begin(),
        arr.end(),
        std::back_inserter(bytearray),
        [](json11::Json b) -> uint8_t { return (uint8_t) b.int_value(); }
    );

    return bytearray;
  }

  SettlementPkg static deserialize(const string &json) noexcept(false) {
    string err;
    const auto ack_json = json11::Json::parse(json, err);

    if (!err.empty()) {
      throw (string("cannot parse ack message: ") + err.c_str());
    }

    bytes tx_one = jsonArrayToBytes(ack_json[TX_ONE].array_items());
    bytes tx_two = jsonArrayToBytes(ack_json[TX_TWO].array_items());
    bytes tx_one_c = jsonArrayToBytes(ack_json[TX_ONE_CANCEL].array_items());
    bytes tx_two_c = jsonArrayToBytes(ack_json[TX_ONE_CANCEL].array_items());

    return SettlementPkg(
        ack_json[TX_ONE_ID].string_value(),
        ack_json[TX_ONE_CANCEL_ID].string_value(),
        tx_one,
        tx_two,
        tx_one_c,
        tx_two_c
    );
  }

};

using PeerList=std::set<Peer>;

class FairnessProtocol {
 public:
  Peer me;
  SettlementPkg msg;
  enum Stage {
    INIT,
    DISSEMINATE,
    SENDACK,
    RECEIVEACK,
    SENDTXONE,
    SENDTXTWO,
  } stage;

  struct Time {
      sgx_time_t time_second;
      sgx_time_source_nonce_t time_source_nonce;
      sgx_time_t period;

      void getTime() {
          int ret;
          int retry = 10;
          do {
              ret = sgx_create_pse_session();
          } while(ret == SGX_ERROR_BUSY && retry--);

          ret = sgx_get_trusted_time(&time_second, &time_source_nonce);
          if (ret != SGX_SUCCESS) {
              LL_CRITICAL("cannot get sgx trusted time");
          }
          sgx_close_pse_session();
      }

      

      bool passTime() {
          Time cur_time;
          cur_time.getTime();
          return (!memcmp(&cur_time.time_source_nonce, time_source_nonce, 
                      sizeof(sgx_time_source_nonce_t))) 
              && (cur_time.time_second >= time_second + period);
      }
  } start_time;

  // if a follower does not see TX_1 by TIMEOUT_T1, it broadcasts TX_1_Cancel
  // if a leader (or a follower) sees TX_1 on chain 1, it broadcast TX_2 to chain 2
  // if a follower sees TX_1_Cancel on chain 1, it broadcast TX_2_Cancel to chain 2
  // TODO modify the timeouts
  const static sgx_time_t TIMEOUT_T1_SECOND = 2; //60 * 15;
  //const static sgx_time_t TIMEOUT_T2_SECOND = 5; //60 * 10 * 6;
  //const static int N_PEER_SERVERS = 5;
  
  FairnessProtocol(const Peer &me) : me(me) {}
  
  void txOneConfirmed(const merkle_proof_t *proof);
  void foundTxOneInMempool(const bytes &txOneinMempool);
  void notFoundTxOneInMempool();
};

class Leader : public FairnessProtocol {
 private:
  vector<Peer> peers;
  vector<bool> peers_ack;

 public:
  // initialize
  Leader(const Peer &me, const vector<Peer> &peers);

  void setMessage(SettlementPkg &&msg);

  // send msg to all peers and wait for ACKs
  void disseminate() noexcept(false);

  void receiveAck(const unsigned char *_ack, size_t size);
};

class Follower : FairnessProtocol {
 private:
  Peer leader;

 public:
  // create a TLS server
  Follower(const Peer &me, const Peer &leader);
  ~Follower() {}

  // simply send ack
  void receiveFromLeader(const unsigned char *msg, size_t size, unsigned char *tx1_id);
};

}
}
} // namespace exch::fairness

#endif //PROJECT_FAIRNESS_H
