#!/bin/bash -e

for i in `seq 1 5`;
do
    filename=CA$i
    openssl req \
        -nodes -newkey rsa:4096 \
        -keyout $filename.key \
        -out $filename.csr \
        -subj /C=US/ST=AB/O=exch/CN=exch-dummy-CA-$i
    openssl x509 -signkey $filename.key -in $filename.csr -req -days 365 -out $filename.crt
done
