#!/bin/bash

ROOTDIR=$( cd "$( dirname "${BASH_SOURCE[0]}")/.." && pwd )

docker_image=bl4ck5un/tesseract-sgx-sdk
docker_name=tesseract
docker_shell=bash

which docker >/dev/null || {
  echo "ERROR: Please install Docker first."
  exit 1
}

docker pull $docker_image

# Start dockerhost
if [ ! "$(docker ps -q -f name=dockerhost)" ]; then
    docker run --name 'dockerhost' \
      --cap-add=NET_ADMIN --cap-add=NET_RAW \
      --restart on-failure \
      -d qoomon/docker-host
fi

# Start SGX Rust Docker container.
if [ ! "$(docker ps -q -f name=$docker_name)" ]; then
  if [ "$(docker ps -aq -f name=$docker_name)" ]; then
    docker start $docker_name
    docker exec -it $docker_name $docker_shell
  else
    docker run -it \
      --name "$docker_name" \
      --link 'dockerhost' \
      -v ${ROOTDIR}/src:/code \
      -e "TESSERTACT_BUILD_CONFIG=Debug" \
      -e "SGX_SDK=/opt/intel/sgxsdk" \
      -w /build \
      "$docker_image" \
      /usr/bin/env $docker_shell
  fi
else
  docker exec -i -t $docker_name $docker_shell
fi
