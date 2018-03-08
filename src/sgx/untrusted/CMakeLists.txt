set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} ${SGX_COMMON_CFLAGS} -fPIC -Wall -Wno-sign-compare -Wno-deprecated")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} ${CMAKE_C_FLAGS} -std=c++11")

set(LIB_MBEDTLS_PATH "${MBEDTLS_SGX_ROOT_DIR}/lib/libmbedtls_sgx_u.a")

set_directory_properties(PROPERTIES
        ADDITIONAL_MAKE_CLEAN_FILES Enclave_u.c
        ADDITIONAL_MAKE_CLEAN_FILES Enclave_u.h)

add_custom_command(
        OUTPUT ${CMAKE_CURRENT_SOURCE_DIR}/Enclave_u.c ${CMAKE_CURRENT_SOURCE_DIR}/Enclave_u.h
        COMMAND ${SGX_EDGER8R} --untrusted Enclave.edl
        --search-path ${CMAKE_CURRENT_SOURCE_DIR}/../Enclave/ # Enclave.edl
        --search-path ${SGX_SDK}/include
        --search-path ${MBEDTLS_SGX_ROOT_DIR}/lib # mbedtls_sgx.edl
        WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
)

add_executable(exch exch.cpp
        fairness.cpp
        interrupt.cpp
        rpc.cpp
        enclave_rpc.cpp
        merkpath/merkpath.cpp
        merkle_data.cpp
        ../common/utils.cpp
        Utils.cpp
        tls_server_threaded_u.cpp
        Enclave_u.c
        Enclave_u.h
        mbedtls_error.c
        mbedtls_net.c
        config.cpp)

add_executable(enclave_test
        enclave_test.cpp Utils.cpp
        Enclave_u.c Enclave_u.h
        merkpath/merkpath.cpp
        merkle_data.cpp
        ../common/utils.cpp
        )

add_executable(exch-keygen exch-keygen.cpp key_u.cpp Utils.cpp
        Enclave_u.c Enclave_u.h
        ../common/base64.cpp)

add_executable(exch-merkleproof
        exch-merkleproof.cpp
        merkpath/merkpath.cpp
        rpc.cpp
        ../common/utils.cpp
        merkle_data.cpp)

find_package(Jsoncpp REQUIRED)
find_package(JsonCppRpc REQUIRED)
find_package(CURL REQUIRED)
find_package(Boost REQUIRED COMPONENTS program_options filesystem)
find_package(OpenSSL REQUIRED)
find_package(Log4CXX REQUIRED)

include_directories(
        ${CURL_INCLUDE_DIRS}
        ${JSONCPP_INCLUDE_DIRS}/${JSONCPP_INCLUDE_PREFIX}
        ${JSONRPCCPP_INCLUDE_DIRS}
        ${SGXSDK_INCLUDE_DIRS}
        ${MBEDTLS_SGX_ROOT_DIR}/include
        ${Boost_INCLUDE_DIRS}
        ${OPENSSL_INCLUDE_DIR}
        ${LOG4CXX_INCLUDE_DIR}
)


target_link_libraries(exch
        ${CURL_LIBRARIES}
        ${JSONCPP_LIBRARIES}
        ${JSONRPCCPP_LIBRARIES}
        ${LOG4CXX_LIBRARY}
        ${Boost_LIBRARIES}
        ${OPENSSL_CRYPTO_LIBRARY}
        -L${SGX_LIBRARY_PATH} -l${SGX_URTS_LIB} -l${SGX_USVC_LIB}
        ${LIB_MBEDTLS_PATH}
        -lpthread)

target_link_libraries(exch-keygen
        ${Boost_LIBRARIES}
        -L${SGX_LIBRARY_PATH} -l${SGX_URTS_LIB} -l${SGX_USVC_LIB}
        ${LIB_MBEDTLS_PATH}
        -lpthread)

target_link_libraries(exch-merkleproof
        ${CURL_LIBRARIES}
        ${JSONCPP_LIBRARIES}
        ${JSONRPCCPP_LIBRARIES}
        ${Boost_LIBRARIES}
        ${LOG4CXX_LIBRARY}
        ${OPENSSL_CRYPTO_LIBRARY}
        )

target_link_libraries(enclave_test
        ${LOG4CXX_LIBRARY}
        ${OPENSSL_CRYPTO_LIBRARY}
        -L${SGX_LIBRARY_PATH} -l${SGX_URTS_LIB} -l${SGX_USVC_LIB}
        ${LIB_MBEDTLS_PATH}
        -lpthread)

add_dependencies(exch enclave)

add_custom_command(TARGET exch
        POST_BUILD
        COMMAND cp -f ${CMAKE_CURRENT_SOURCE_DIR}/logging.conf ${CMAKE_RUNTIME_OUTPUT_DIRECTORY}
        COMMENT "Installing the configuration files")
