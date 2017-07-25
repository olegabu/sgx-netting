cmake_minimum_required(VERSION 3.7)
project(sgx_netting)

set(SGX_SDK $ENV{SGX_SDK})
set(SGX_ARCH x64)
set(SGX_MODE SIM CACHE STRING "SGX mode: SIM or HW") # SGX mode: sim, hw
set(COMPILE_EXAMPLES NO CACHE BOOL "Build examples")
set(SGX_BUILD DEBUG CACHE STRING "Build: DEBUG, PRERELEASE or RELEASE")

set( CMAKE_VERBOSE_MAKEFILE on )

include (cmake/Init.cmake)
include (cmake/ConfigSGX.cmake)

set(CMAKE_CXX_STANDARD 11)

include_directories(app enclave common)

add_subdirectory(app)
add_subdirectory(enclave)
add_definitions(-std=c++11)