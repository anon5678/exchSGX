#!/bin/sh
jsonrpcstub bitcoind_api.json --cpp-client bitcoindRPCClient
jsonrpcstub enclave-rpc.json \
    --cpp-server=exch::rpc::AbsServer \
    --cpp-server-file=enclave-rpc-server.h \
    --cpp-client=exch::rpc::AbsClient \
    --cpp-client-file=enclave-rpc-client.h
