#!/bin/bash

ROOTDIR=$( cd "$( dirname "${BASH_SOURCE[0]}")/.." && pwd )

DEV_IMAGE=bl4ck5un/tesseract-sgx-sdk
DEV_SHELL=bash

which docker >/dev/null || {
  echo "ERROR: Please install Docker first."
  exit 1
}

# Start SGX Rust Docker container.
docker run --rm -t -i \
  --name "tesseract-devel" \
  -v ${ROOTDIR}/src:/code \
  -e "TESSERTACT_BUILD_CONFIG=Debug" \
  -e "SGX_SDK=/opt/intel/sgxsdk" \
  -w /code/build \
  "$DEV_IMAGE" \
  /usr/bin/env $DEV_SHELL
