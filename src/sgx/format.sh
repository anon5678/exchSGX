#!/usr/bin/env bash

clang-format -style=file -i Enclave/*.cpp untrusted/*.cpp Enclave/*.h untrusted/*.h untrusted/rpc/*.cpp untrusted/rpc/*.h
