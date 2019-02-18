#include "state.h"

using namespace exch::enclave;
using namespace exch::enclave::fairness;

BlockFIFO<1000> state::blockFIFO;
BalanceBook state::balanceBook;

sgx_thread_mutex_t state_mutex = SGX_THREAD_MUTEX_INITIALIZER;

const int State::FOLLOWER_TIMEOUT_SECONDS;

bool State::addPeer(const securechannel::Peer &peer)
{
  sgx_thread_mutex_lock(&state_mutex);
  auto r = fairnessPeers.insert(peer);
  sgx_thread_mutex_unlock(&state_mutex);
  return r.second;
}

void State::removePeer(const string &hostname, uint16_t port)
{
  sgx_thread_mutex_lock(&state_mutex);
  auto it = fairnessPeers.begin();
  for (it = fairnessPeers.begin(); it != fairnessPeers.end(); it++) {
    if (it->getHostname() == hostname && it->getPort() == port) break;
  }
  fairnessPeers.erase(it);
  sgx_thread_mutex_unlock(&state_mutex);
}

void State::setLeader(const securechannel::Peer &peer)
{
  sgx_thread_mutex_lock(&state_mutex);
  currentLeader = peer;
  sgx_thread_mutex_unlock(&state_mutex);
}

void State::setSelf(bool is_leader, const securechannel::Peer &self)
{
  sgx_thread_mutex_lock(&state_mutex);
  this->isLeader = is_leader;
  this->self = self;

  securechannel::Peer self_info(
      self.getHostname(),
      self.getPort(),
      self.getPublicKey(),
      self.getSecretKey());

  if (!is_leader) {
    // TODO: replace this with sealed keys from untrusted world
    // string leaderSk;
    // string leaderPk = nacl_crypto_box_keypair(&leaderSk);
    Peer leader_info(
        currentLeader.getHostname(),
        currentLeader.getPort(),
        currentLeader.getPublicKey());

    this->currentFollower = new fairness::Follower(self_info, leader_info);
  } else {
    for (const auto &p : this->fairnessPeers) {
      LL_NOTICE("found peer %s:%d", p.getHostname().c_str(), p.getPort());
    }

    LL_NOTICE(
        "found leader at %s:%d",
        this->currentLeader.getHostname().c_str(),
        this->currentLeader.getPort());

    // FIXME: avoid copy
    vector<Peer> peerList;
    copy(
        this->fairnessPeers.begin(),
        this->fairnessPeers.end(),
        back_inserter(peerList));

    this->currentProtocol = new fairness::Leader(self_info, peerList);
  }
  sgx_thread_mutex_unlock(&state_mutex);
}

fairness::Leader *State::initFairnessProtocol(SettlementPkg &&msg)
{
  sgx_thread_mutex_lock(&state_mutex);

  // record the current protocol
  // auto p = new fairness::Leader(leader_info, peerList, move(msg));
  // this->currentProtocol = p;

  this->currentProtocol->setMessage(move(msg));

  sgx_thread_mutex_unlock(&state_mutex);

  return this->currentProtocol;
}
