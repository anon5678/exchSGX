#ifndef PROJECT_FAIRNESS_H
#define PROJECT_FAIRNESS_H

// this class implements pi_prac
class fairnessProtocol {
 public:
  const static N_PEER_SERVERS = 5;

  // methods for backup (i.e. servers)

  // simply send ack
  void receive_from_tesseract();
  // broadcast cancellation
  void tx_one_not_appear();
  // broadcast TX2
  void tx_one_confirmed();
  // broadcast TX2 cancellation
  void tx_one_canceled();
};

class fairnessMessage {
 private:
  vector<uint8_t> cipher;
};

#endif //PROJECT_FAIRNESS_H
