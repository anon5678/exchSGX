bitcoin-cli stop
litecoin-cli stop

sleep 2s

rm -rf ~/.bitcoin/regtest
rm -rf ~/.litecoin/regtest

sleep 2s

bitcoind --daemon
litecoind --daemon

sleep 5s

node bitcoin-deposit.js ${1:-4}
node litecoin-deposit.js ${1:-4}

