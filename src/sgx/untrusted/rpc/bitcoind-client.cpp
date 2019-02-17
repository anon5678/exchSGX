#include "bitcoind-client.h"

#include <stdexcept>
#include <string>
#include <iostream>

#include <jsonrpccpp/common/errors.h>

int Bitcoind::getblockcount() {
  try {
    return this->bitcoind_client.getblockcount();
  }
  catch (const jsonrpc::JsonRpcException &e) {
    throw std::runtime_error("jsonrpc error: " + string(e.what()));
  }
}

string Bitcoind::getblockhash(int block_height) noexcept (false){
  try {
    return this->bitcoind_client.getblockhash(block_height);
  } catch (const jsonrpc::JsonRpcException &e) {
    throw bitcoinRPCException(e.GetCode(), e.GetMessage());
  }
}

string Bitcoind::getblockheader(const string &block_hash, bool format) {
  try {
    return this->bitcoind_client.getblockheader(block_hash, format);
  }
  catch (const jsonrpc::JsonRpcException &e) {
    throw bitcoinRPCException(e.GetCode(), e.GetMessage());
  }
}

Json::Value Bitcoind::getblock(const string &block_hash) {
  try {
    return this->bitcoind_client.getblock(block_hash);
  }
  catch (const jsonrpc::JsonRpcException &e) {
    throw bitcoinRPCException(e.GetCode(), e.GetMessage());
  }
}

Json::Value Bitcoind::getrawtransaction(const string &txn_hash, bool JSONformat) {
  try {
    Json::Value ret = this->bitcoind_client.getrawtransaction(txn_hash, true);

    if (!JSONformat) {
      return ret["hex"];
    }

    return ret;
  }
  catch (const jsonrpc::JsonRpcException &e) {
    throw bitcoinRPCException(e.GetCode(), e.GetMessage());
  }
}
