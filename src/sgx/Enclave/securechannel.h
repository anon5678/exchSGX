#ifndef TESSERACT_SECURECHANNEL_H
#define TESSERACT_SECURECHANNEL_H

#include <cstdint>
#include <string>

#include "crypto_box.h"
#include "json11.hpp"
#include "log.h"
#include "pprint.h"
#include "utils.h"

namespace exch
{
namespace enclave
{
namespace securechannel
{
using Nonce = uint64_t;
using std::string;

struct Box {
  std::string cipher;
  std::string nonce;
  Box(const std::string &cipher, const std::string &nonce)
      : cipher(cipher), nonce(nonce)
  {
  }

  size_t size() { return cipher.size() + nonce.size(); }

  string serialize() const
  {
    json11::Json json =
        json11::Json::object{{"cipher", cipher}, {"nonce", nonce}};
    return json.dump();
  }

  Box static deserialize(const string &json) noexcept(false)
  {
    string err;
    const auto box_json = json11::Json::parse(json, err);

    if (!err.empty()) {
      throw(string("cannot parse box message: ") + err.c_str());
    }

    return Box(
        box_json["cipher"].string_value(), box_json["nonce"].string_value());
  }
};

class Peer
{
 private:
  std::string hostname;
  uint16_t port;
  Nonce nonce;
  unsigned char publicKey[crypto_box_PUBLICKEYBYTES];
  unsigned char secretKey[crypto_box_SECRETKEYBYTES];

 public:
  Peer() = default;
  Peer(
      const std::string &hostname,
      uint16_t port,
      const std::string &publicKey,
      const std::string &secretKey)
      : Peer(hostname, port, publicKey)
  {
    if (crypto_box_SECRETKEYBYTES != secretKey.size())
      throw "secret key size not right";
    memcpy(this->secretKey, secretKey.data(), secretKey.size());
  }

  Peer(const std::string &hostname, uint16_t port, const std::string &publicKey)
      : hostname(hostname), port(port), nonce(0)
  {
    if (crypto_box_PUBLICKEYBYTES != publicKey.size())
      throw std::invalid_argument("public key size not right");
    memcpy(this->publicKey, publicKey.data(), publicKey.size());
  }

  const std::string &getHostname() const { return hostname; }

  uint16_t getPort() const { return port; }

  std::string getPublicKey() const
  {
    return std::string((char *)publicKey, sizeof publicKey);
  };

  std::string getSecretKey() const
  {
    return std::string((char *)secretKey, sizeof secretKey);
  }

  string getNonce() const
  {
    string n = string((char *)&nonce, sizeof nonce);
    n.insert(n.end(), crypto_box_NONCEBYTES - n.size(), 0x00);
    return n;
  }

  Box createBoxToPeer(const Peer &peer, const std::string &msg)
  {
    std::string box = nacl_crypto_box(
        msg, getNonce(), peer.getPublicKey(), this->getSecretKey());
    Box b(box, getNonce());
    nonce++;
    return b;
  }

  std::string openBoxFromPeer(const Box &box, const Peer &peer)
  {
    return nacl_crypto_box_open(
        box.cipher, box.nonce, peer.getPublicKey(), this->getSecretKey());
  }

  bool operator<(const Peer &rhs) const
  {
    return hostname == rhs.hostname ? port < rhs.port : hostname < rhs.hostname;
  }

  bool operator==(const Peer &rhs) const
  {
    return hostname == rhs.hostname && port == rhs.port;
  }

  string toString() const { return hostname + ":" + std::to_string(port); }
};

}  // namespace securechannel
}  // namespace enclave
}  // namespace exch

#endif  // PROJECT_SECURECHANNEL_H
