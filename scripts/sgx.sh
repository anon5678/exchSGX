#!/bin/sh -e

SGX_SDK_BIN=sgx_sdk.bin
wget -O $SGX_SDK_BIN https://download.01.org/intel-sgx/linux-1.9/sgx_linux_ubuntu16.04.1_x64_sdk_1.9.100.39124.bin
chmod a+x $SGX_SDK_BIN
echo -e 'no\n/opt/intel' | sudo ./$SGX_SDK_BIN
echo 'source /opt/intel/sgxsdk/environment' >> ~/.zshrc
