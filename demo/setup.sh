rm -rf ~/Library/Application\ Support/Bitcoin/*
rm -rf ~/Library/Application\ Support/Litecoin/*

cp ../conf/bitcoin.conf ~/Library/Application\ Support/Bitcoin/
cp ../conf/litecoin.conf ~/Library/Application\ Support/Litecoin/

./bitcoin-0.17.1/bin/bitcoind --daemon
./litecoin-0.16.3/bin/litecoind --daemon

sleep 2s

node bitcoin-deposit.js
node litecoin-deposit.js
