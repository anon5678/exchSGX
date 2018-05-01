For Developers
==============

The recommended way of building Tesseract is to use the suppied `docker image`_.

``scripts/sgx-enter.sh`` sets up the docker container properly and gives you a bash
to build the project:

.. code-block:: bash
    
    cd scripts
    ./sgx-enter.sh
    root@1a14107187db:/build# cmake /code/sgx
    root@1a14107187db:/build# make
    
    
.. _docker image: https://hub.docker.com/r/bl4ck5un/tesseract-sgx-sdk/
