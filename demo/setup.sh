rm -rf ~/Library/Application Support/Bitcoin/regtest
rm -rf ~/Library/Application Support/Litecoin/regtest

./bitcoin-0.17.1/bin/bitcoind --daemon
./litecoin-0.16.3/bin/litecoind --daemon

node bitcoin-deposit.js
node litecoin-deposit.js
