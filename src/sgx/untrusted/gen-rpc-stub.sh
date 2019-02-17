#!/bin/sh
jsonrpcstub bitcoind_rpc.json --cpp-client bitcoindRPCClient --cpp-client-file=bitcoind-rpc-client.h
jsonrpcstub enclave-rpc.json \
    --cpp-server=exch::rpc::AbsServer \
    --cpp-server-file=enclave-rpc-server.h \
    --cpp-client=exch::rpc::AbsClient \
    --cpp-client-file=enclave-rpc-client.h
