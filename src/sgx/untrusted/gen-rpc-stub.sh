#!/bin/sh
jsonrpcstub bitcoind_api.json --cpp-client bitcoindRPCClient
jsonrpcstub enclave.json --cpp-server AbstractEnclaveRPC
