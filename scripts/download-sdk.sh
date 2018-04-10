#!/bin/bash

SGX_SDK_URL=https://download.01.org/intel-sgx/linux-2.1.2/ubuntu64-desktop/sgx_linux_x64_sdk_2.1.102.43402.bin

TEMP=$(mktemp -d)

pushd $TEMP
curl $SGX_SDK_URL > sgx_linux_sdk.bin
chmod u+x sgx_linux_sdk.bin
echo -e 'no\n/opt/intel' | sudo ./sgx_linux_sdk.bin
popd
