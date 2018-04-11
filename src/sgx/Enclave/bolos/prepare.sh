#!/bin/bash
if [[ -d secp256k1 ]]; then rm -rf secp256k1; fi;
git clone https://github.com/bitcoin-core/secp256k1
pushd secp256k1
git checkout 119949232a243396ba1462676932a11022592b59
patch -p0 < ../patches/secp256k1.patch
pushd src
popd
./autogen.sh && \
./configure \
    --disable-shared \
    --enable-endomorphism \
    --enable-module-recovery \
    --enable-tests=no \
    --enable-openssl-tests=no \
    --enable-exhaustive-tests=no \
    --with-bignum=no \
    --prefix=$PWD/../../secp256k1 && \
make -j && make install
popd
