#include "bitcoind-client.h"

#include <iostream>
#include <stdexcept>
#include <string>

#include <jsonrpccpp/common/errors.h>

int Bitcoind::getblockcount()
{
  try {
    return this->bitcoind_stub.getblockcount();
  } catch (const jsonrpc::JsonRpcException &e) {
    throw BitcoindRPCException(e.GetCode(), e.GetMessage());
  }
}

string Bitcoind::getblockhash(int block_height) noexcept(false)
{
  try {
    return this->bitcoind_stub.getblockhash(block_height);
  } catch (const jsonrpc::JsonRpcException &e) {
    throw BitcoindRPCException(e.GetCode(), e.GetMessage());
  }
}

string Bitcoind::getblockheader(const string &block_hash, bool format)
{
  try {
    return this->bitcoind_stub.getblockheader(block_hash, format);
  } catch (const jsonrpc::JsonRpcException &e) {
    throw BitcoindRPCException(e.GetCode(), e.GetMessage());
  }
}

Json::Value Bitcoind::getblock(const string &block_hash)
{
  try {
    return this->bitcoind_stub.getblock(block_hash);
  } catch (const jsonrpc::JsonRpcException &e) {
    throw BitcoindRPCException(e.GetCode(), e.GetMessage());
  }
}

Json::Value Bitcoind::getrawtransaction(const string &txn_hash, bool JSONformat)
{
  try {
    Json::Value ret = this->bitcoind_stub.getrawtransaction(txn_hash, true);

    if (!JSONformat) {
      return ret["hex"];
    }

    return ret;
  } catch (const jsonrpc::JsonRpcException &e) {
    throw BitcoindRPCException(e.GetCode(), e.GetMessage());
  }
}

void Bitcoind::sendrawtransaction(const string &tx_hex)
{
  try {
    this->bitcoind_stub.sendrawtransaction(tx_hex);
  } catch (const jsonrpc::JsonRpcException &e) {
    BitcoindRPCException err(e.GetCode(), e.GetMessage());
    if (err.getCode() != 0) throw err;
  }
}

void Bitcoind::generatetoaddress(int nblocks, const string &tx_hash)
{
  try {
    this->bitcoind_stub.generatetoaddress(nblocks, tx_hash);
  } catch (const jsonrpc::JsonRpcException &e) {
    throw BitcoindRPCException(e.GetCode(), e.GetMessage());
  }
}
