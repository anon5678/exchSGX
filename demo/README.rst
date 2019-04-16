Tesseract
=========

How to run the demo of fairness protocol
----------------------------------------


Setup Bitcoin Client and Litecoin Client
~~~~~~~~~~~~~~~~~~~~

Following the `official instructions`_ to install the Bitcoin client and Litecoin client on your system. Take Bitcoin as an example, On Ubuntu:

.. code-block:: bash

    sudo apt-add-repository --yes ppa:bitcoin/bitcoin
    sudo apt-get update
    sudo apt-get install bitcoin-qt

Copy the supplied configuration file ``conf/bitcoin.conf`` to the right place. On Linux:

.. code-block:: bash

    mkdir -p ~/.bitcoin && ln -sf $(pwd)/conf/bitcoin.conf ~/.bitcoin


Launch ``bitcoin-qt``.

Similar for Litecoin.

Deposit to the Exchange
~~~~~~~~~~~~~~~~~~~~~~~

After launching Bitcoin Client and Litecoin Client, run scripts to deposit money to the exchange for trading:

.. code-block:: bash

    cd demo
    npm install bitcoind-rpc
    node bitcoin-deposit.js
    node litecoin-deposit.js


Build and Run Tesseract
~~~~~~~~~~~~~~~~~~~~~~~

The recommended way of building Tesseract is to use the suppied `docker image`_. ``scripts/sgx-enter.sh`` sets up the docker container properly and gives you a bash:

.. code-block:: bash

    cd scripts
    ./sgx-enter.sh
    root@1a14107187db:/build# cmake /code/sgx
    root@1a14107187db:/build# make -j


Make sure a Bitcoin client is running. In the docker container, Run the fairness demo by:

.. code-block:: bash

    # launch a follower
    root@1a14107187db:/build# ./exch &
    # launch another folloewr
    root@1a14107187db:/build# ./exch &
    # launch the leader
    root@1a14107187db:/build# ./exch -l

To demostrate a case when there is failure in sending the first settlement transaction and the system falls into cancelling transactions, run the exchange by:

.. code-block:: bash

    # launch a follower
    root@1a14107187db:/build# ./exch -f &
    # launch another folloewr
    root@1a14107187db:/build# ./exch -f &
    # launch the leader
    root@1a14107187db:/build# ./exch -l -f

You may want to run the above in three terminal windows so the output doesn't mix up. To get a bash from any terminal window, run ``scripts/sgx-enter.sh``.

.. _docker image: https://hub.docker.com/r/bl4ck5un/tesseract-sgx-sdk/
.. _official instructions: https://bitcoin.org/en/full-node
