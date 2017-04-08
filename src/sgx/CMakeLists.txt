# need 3.0 for multiple line strings
cmake_minimum_required(VERSION 3.0)

set(SGX_SDK /opt/intel/sgxsdk)
set(SGX_ARCH x64)
set(SGX_MODE SIM CACHE STRING "SGX mode: SIM or HW") # SGX mode: sim, hw
set(COMPILE_EXAMPLES NO CACHE BOOL "Build examples")
set(SGX_BUILD DEBUG CACHE STRING "Build: DEBUG, PRERELEASE or RELEASE")

include (cmake/Init.cmake)
include (cmake/ConfigSGX.cmake)

set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR})
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR})

set(MBEDTLS_SGX_ROOT_DIR "${CMAKE_SOURCE_DIR}/mbedtls-SGX/")

add_subdirectory(untrusted)
add_subdirectory(Enclave)
