#!/bin/bash

set -e

BASE_DIR=$( cd "$( dirname "${BASH_SOURCE[0]}")" && pwd )

pushd ${BASE_DIR}

test -d secp256k1 && rm -rf secp256k1

git clone https://github.com/bitcoin-core/secp256k1

pushd secp256k1
git checkout 119949232a243396ba1462676932a11022592b59
patch -p0 < ../patches/secp256k1.patch
popd

popd
