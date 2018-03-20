#include "bitcoind-rpc.h"
#include "bitcoindrpcclient.h"

#include <stdexcept>
#include <string>
#include <iostream>

#include <jsonrpccpp/common/errors.h>

const string bitcoinRPC::BITCOIND_RPC_ADDR =
    "http://exch:goodpass@localhost:8332";

int bitcoinRPC::getblockcount() {
  try {
    return this->bitcoindClient.getblockcount();
  }
  catch (const jsonrpc::JsonRpcException &e) {
    throw std::runtime_error("jsonrpc error: " + string(e.what()));
  }
}

string bitcoinRPC::getblockhash(int block_height) {
  try {
    return this->bitcoindClient.getblockhash(block_height);
  } catch (const jsonrpc::JsonRpcException &e) {
    bitcoinRPCException err(e.GetCode(), e.GetMessage());
    throw err;
  }
}

string bitcoinRPC::getblockheader(const string &block_hash, bool format) {
  try {
    return this->bitcoindClient.getblockheader(block_hash, format);
  }
  catch (const jsonrpc::JsonRpcException &e) {
    bitcoinRPCException err(e.GetCode(), e.GetMessage());
    throw err;
  }
}

Json::Value bitcoinRPC::getblock(const string &block_hash) {
  try {
    return this->bitcoindClient.getblock(block_hash);
  }
  catch (const jsonrpc::JsonRpcException &e) {
    bitcoinRPCException err(e.GetCode(), e.GetMessage());
    throw err;
  }
}

Json::Value bitcoinRPC::getrawtransaction(const string &txn_hash, bool JSONformat) {
  try {
    Json::Value ret = this->bitcoindClient.getrawtransaction(txn_hash, true);

    if (!JSONformat) {
      return ret["hex"];
    }

    return ret;
  }
  catch (const jsonrpc::JsonRpcException &e) {
    bitcoinRPCException err(e.GetCode(), e.GetMessage());
    throw err;
  }
}
