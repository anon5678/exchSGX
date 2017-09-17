#!/bin/bash

for i in `seq 1 5`; do
    id="client$i"
    ../sgx/build/exch-keygen -g $id --enclave ../sgx/build/enclave.signed.so \
        --subject "C=US,O=exch,CN=exch-enclave-$i"
    openssl x509 -req -in $id.csr \
        -CA CA1.crt -CAkey CA1.key -CAcreateserial \
        -out $id.crt -days 365 -sha256

    sleep 2
done
