add_definitions(-DIN_ENCLAVE -DSGX)

add_custom_command(
        OUTPUT ${CMAKE_CURRENT_SOURCE_DIR}/Enclave_t.c ${CMAKE_CURRENT_SOURCE_DIR}/Enclave_t.h
        COMMAND ${SGX_EDGER8R} --trusted ../common/Enclave.edl
        --search-path ${SGX_SDK}/include
        WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
)

FILE(GLOB BITCOIN_SRC_FILES "bitcoin/*.cpp")
set(BITCOIN_SRC_FILES
        ${BITCOIN_SRC_FILES}
        bitcoin/primitives/block.cpp
        bitcoin/primitives/transaction.cpp
        bitcoin/crypto/sha1.cpp
        bitcoin/crypto/sha256.cpp
        bitcoin/crypto/sha512.cpp
        bitcoin/crypto/ripemd160.cpp
        bitcoin/crypto/hmac_sha512.cpp
        bitcoin/script/script_error.cpp
        bitcoin/script/interpreter.cpp
        bitcoin/script/script.cpp
        libsecp256k1.a)

set(SOURCE_FILES
        # basic stuff
        Enclave_t.c
        Enclave_t.h
        log.cpp
        pprint.cpp
        bytestream.cpp
        utils.cpp
        ../common/utils.cpp
        ../common/json11.cpp
        ../common/base64.cpp
        enclave_test.cpp

        # fairness
        fairness.cpp
        securechannel.cpp

        # enclave state
        blockfifo.hpp
        balancebook.hpp
        state.cpp
        state_blockfifo.cpp
        state_balance.cpp
        state_fairness.cpp

        # bitcoin
        ${BITCOIN_SRC_FILES}

        # nacl
        nacl/tweetnacl.c
        nacl/randombytes.c
        nacl/crypto_box/wrapper-keypair.cpp
        nacl/crypto_box/wrapper-box.cpp
        nacl/crypto_box/wrapper-open.cpp
        )

add_library(enclave SHARED ${SOURCE_FILES})

include_directories(
        ${CMAKE_CURRENT_SOURCE_DIR}
        ${SGX_SDK}/include
        ${SGX_SDK}/include/tlibc
        ${SGX_SDK}/include/libcxx
        ${MBEDTLS_SGX_ROOT_DIR}/include
        ${CMAKE_SOURCE_DIR}/common
        bitcoin
        nacl
        bolos/secp256k1/include
)

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} ${SGX_COMMON_CFLAGS} -Wall -Wno-deprecated -nostdinc -fvisibility=hidden -fpie -fstack-protector")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} ${CMAKE_C_FLAGS} -std=c++11 -nostdinc++")

set_target_properties(enclave PROPERTIES PREFIX "")

set(SECP256K1_LIB_PATH ${CMAKE_CURRENT_BINARY_DIR}/secp256k1/lib/libsecp256k1.a)

set_directory_properties(PROPERTIES
        ADDITIONAL_MAKE_CLEAN_FILES Enclave_t.c
        ADDITIONAL_MAKE_CLEAN_FILES Enclave_t.h
        ADDITIONAL_MAKE_CLEAN_FILES ${SECP256K1_LIB_PATH})

target_link_libraries(enclave "${SGX_COMMON_CFLAGS} \
    -Wl,--no-undefined -nostdlib -nodefaultlibs -nostartfiles -L${SGX_LIBRARY_PATH} \
    -Wl,--whole-archive -l${SGX_TRTS_LIB} -Wl,--no-whole-archive \
    -Wl,--start-group \
        -lsgx_tstdc -lsgx_tcxx -lsgx_tcrypto -l${SGX_TSVC_LIB} ${SECP256K1_LIB_PATH} \
    -Wl,--end-group \
    -Wl,-Bstatic -Wl,-Bsymbolic -Wl,--no-undefined \
    -Wl,-pie,-eenclave_entry -Wl,--export-dynamic \
    -Wl,--defsym,__ImageBase=0")

add_custom_command(OUTPUT libsecp256k1.a
        COMMAND ./autogen.sh
        COMMAND env CPPFLAGS=-fPIC ./configure
        --enable-shared
        --enable-endomorphism
        --enable-module-recovery
        --enable-tests=no
        --enable-openssl-tests=no
        --enable-exhaustive-tests=no
        --with-bignum=no
        --prefix ${CMAKE_CURRENT_BINARY_DIR}/secp256k1
        COMMAND make -Bj
        COMMAND make install
        WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/bolos/secp256k1
        COMMENT "Building secp256k1")

add_custom_command(TARGET enclave
        POST_BUILD
        COMMAND ${SGX_ENCLAVE_SIGNER} sign
        -key Enclave_private.pem
        -config Enclave.config.xml
        -enclave ${CMAKE_LIBRARY_OUTPUT_DIRECTORY}/enclave.so
        -out ${CMAKE_LIBRARY_OUTPUT_DIRECTORY}/enclave.signed.so
        WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
        COMMENT "Signing the enclave. Writing to ${CMAKE_LIBRARY_OUTPUT_DIRECTORY}")