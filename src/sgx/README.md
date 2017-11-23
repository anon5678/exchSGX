Dependencies
============

You need lib support for RPC. For Ubuntu 16.04:

    sudo apt-get -y install build-essential cmake pkg-config
    sudo apt-get -y install libboost-all-dev libssl-dev openssl liblog4cxx-dev libmicrohttpd-dev
    sudo apt-get -y install libjsonrpccpp-dev
    sudo apt-get -y install libjsoncpp-dev libcurl4-openssl-dev

You also need `bitcoind`, which can be installed by (Ubuntu 16.04)

    sudo add-apt-repository ppa:bitcoin/bitcoin
    sudo apt update && sudo apt install bitcoind



Config Bitcoin Daemon
=====================

I use `bitcoin.conf`. See if it suits your need.

    ln -s $PWD/bitcoin.conf ~/.bitcoin/

Run
===

    bitcoind -daemon
    # cd to src/sgx
    mkdir build && cd build
    cmake .. && make

Run the (small) testing excutable:

    ./blockfeeder
