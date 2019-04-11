const lock = require('locks');
const bitcoin = require('bitcoinjs-lib');
const regtest = bitcoin.networks.testnet;
const RpcClient = require('bitcoind-rpc');
const assert = require('assert');
const fs = require('fs');
const file = "../src/sgx/untrusted/test_data/litecoin-deposit"

const config = {
    protocol: 'http',
    user: 'exch',
    pass: 'goodpass',
    host: '127.0.0.1',
    port: '8335',
  };

const rpc = new RpcClient(config);

const addr = ["muEPF2wfm1QdLy3LKocBQiW8g73WpzFq72",     //sgx
              "2NAqCFC8FazvtUzGv23reB9kQyR9JBW48PB",    //alice
              "2NEPd7jWr4mFw2iGeVQvzn5YMZrwL7R7esH",    //bob
              "2MvdHzi7sxRbJTwjcH7wMT7z5GDpiq7ktfJ",    //carl
              "2MuAaNqaBaWTKFPq5CENWmhd58u7zJQLpnG"];   //david


fs.writeFile(file, "", (err) => {
    if (err) return console.log(err);
});

function work(i) {
    if (i == 5) {
        rpc.generate(100, function(err, res) {
            if (err) return console.log(err);
            return;
        });
    } else {
        rpc.generatetoaddress(1, addr[i], function(err, res) {
            if (err) return console.log(err);
            rpc.getblock(res["result"], function(err, res) {
                if (err) return console.log(err);
                console.log(res["result"]["tx"][0]);
                rpc.getrawtransaction(res["result"]["tx"][0], false, function(err, res) {
                    fs.appendFile(file, res["result"] + "\n", (err) => {
                        if (err) return console.log(err);
                        work(i + 1);
                    });
                });
            });
        });
    }
}

work(0);


