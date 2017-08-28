set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} ${SGX_COMMON_CFLAGS} -fPIC -Wno-attributes")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} ${CMAKE_C_FLAGS} -std=c++11")

set(CLIENT_SRC_FILES Enclave_u.c Utils.cpp)

set_directory_properties(PROPERTIES
        ADDITIONAL_MAKE_CLEAN_FILES "Enclave_u.c; Enclave_u.h")

add_custom_command(
        OUTPUT ${CMAKE_CURRENT_SOURCE_DIR}/Enclave_u.c
        COMMAND ${SGX_EDGER8R} --untrusted Enclave.edl
        --search-path ${CMAKE_CURRENT_SOURCE_DIR}/../Enclave/ # Enclave.edl
        --search-path ${SGX_SDK}/include
        --search-path ${MBEDTLS_SGX_ROOT_DIR}/lib # mbedtls_sgx.edl
        WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
)

add_executable(m_server m_server.cpp mbedtls_net.c mbedtls_error.c Enclave_u.c Utils.cpp)
add_executable(exch exch.cpp Utils.cpp Enclave_u.c)
add_executable(enclave_test enclave_test.cpp Utils.cpp Enclave_u.c)

find_package(Jsoncpp REQUIRED)
find_package(JsonCppRpc REQUIRED)
find_package(CURL REQUIRED)

include_directories(
        ${CURL_INCLUDE_DIRS}
        ${JSONCPP_INCLUDE_DIRS}/${JSONCPP_INCLUDE_PREFIX}
        ${JSONRPCCPP_INCLUDE_DIRS}
        ${SGXSDK_INCLUDE_DIRS}
        ${MBEDTLS_SGX_ROOT_DIR}/include
)

set(LIB_MBEDTLS_PATH "${MBEDTLS_SGX_ROOT_DIR}/lib/libmbedtls_sgx_u.a")

target_link_libraries(exch
        ${JSONCPP_LIBRARIES} ${CURL_LIBRARIES}
        ${JSONRPCCPP_LIBRARIES}
        -L${SGX_LIBRARY_PATH} -l${SGX_URTS_LIB} -l${SGX_USVC_LIB}
        ${LIB_MBEDTLS_PATH}
        -lpthread)

target_link_libraries(enclave_test
        -L${SGX_LIBRARY_PATH} -l${SGX_URTS_LIB} -l${SGX_USVC_LIB}
        ${LIB_MBEDTLS_PATH}
        -lpthread)

target_link_libraries(m_server
        -L${SGX_LIBRARY_PATH} -l${SGX_URTS_LIB} -l${SGX_USVC_LIB}
        ${LIB_MBEDTLS_PATH}
        -lpthread)

add_dependencies(m_server enclave)