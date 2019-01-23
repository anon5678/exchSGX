#!/bin/bash

SGX_SDK_URL=https://download.01.org/intel-sgx/linux-2.4/ubuntu18.04-server/sgx_linux_x64_sdk_2.4.100.48163.bin

sudo apt-get install libssl-dev libcurl4-openssl-dev libprotobuf-dev build-essential python

TEMP=$(mktemp -d)

pushd $TEMP
curl $SGX_SDK_URL > sgx_linux_sdk.bin
chmod u+x sgx_linux_sdk.bin
echo -e 'no\n/opt/intel' | sudo ./sgx_linux_sdk.bin
popd
