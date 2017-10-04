
add_custom_command(
    OUTPUT ${CMAKE_CURRENT_SOURCE_DIR}/enclave_t.c
    DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/enclave.edl
    COMMAND ${SGX_EDGER8R} --trusted ${CMAKE_CURRENT_SOURCE_DIR}/enclave.edl
    --search-path ${TC_ROOT_DIR}/Enclave
    --search-path ${SGX_SDK}/include
    WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
)

add_custom_command(
    OUTPUT ${CMAKE_CURRENT_SOURCE_DIR}/enclave_u.h
    DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/enclave.edl
    COMMAND ${SGX_EDGER8R} --untrusted ${CMAKE_CURRENT_SOURCE_DIR}/enclave.edl
    --search-path ${TC_ROOT_DIR}/Enclave
    --search-path ${SGX_SDK}/include
    WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
)

include_directories(
        $(CMAKE_CURRENT_SOURCE_DIR)
        ${SGX_SDK}/include
        ${SGX_SDK}/include/tlibc
        ${SGX_SDK}/include/stlport
        .
)

add_library(enclave SHARED
        enclave_t.c enclave_u.h
        ../common/shared_ptr.h
        ../common/trade.h ../common/serial_trades.h ../common/serial_trades.cpp
        ../common/NotionalMatrix.h
        ../common/SemiLocalAlgorithm.h
        enclave_state.h enclave_state.cpp
        outside.h outside.cpp
        ../common/crypto.h crypto.cpp
        semi_local_compress.cpp)

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} ${SGX_COMMON_CFLAGS} -nostdinc -fvisibility=hidden -fpie -fstack-protector")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} ${CMAKE_C_FLAGS} -nostdinc++ -DENCLAVE")

target_link_libraries(enclave PRIVATE "${SGX_COMMON_CFLAGS}\
    -Wl,--no-undefined -nostdlib -nodefaultlibs -Wl,--no-undefined -nostdlib -nodefaultlibs -nostartfiles -L${SGX_LIBRARY_PATH} \
	-Wl,--whole-archive -l${SGX_TRTS_LIB} -Wl,--no-whole-archive \
	-Wl,--start-group -lsgx_tstdc -lsgx_tcxx -lsgx_tstdcxx -lsgx_tkey_exchange -lsgx_tcrypto -l${SGX_TSVC_LIB} -Wl,--end-group \
	-Wl,-Bstatic -Wl,-Bsymbolic -Wl,--no-undefined \
	-Wl,-pie,-eenclave_entry -Wl,--export-dynamic  \
	-Wl,--defsym,__ImageBase=0 -Wl,--gc-sections   \
	-Wl,--version-script=${CMAKE_CURRENT_SOURCE_DIR}/enclave.lds \
	-L${CMAKE_CURRENT_SOURCE_DIR}")

set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/../app/)
add_custom_command(TARGET enclave
        POST_BUILD
        COMMAND ${SGX_ENCLAVE_SIGNER} sign
        -key enclave_private.pem
        -config enclave.config.xml
        -enclave $<TARGET_FILE:enclave>
        -out ${CMAKE_RUNTIME_OUTPUT_DIRECTORY}/enclave.so
        WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
        COMMENT "Signing the enclave => ${CMAKE_RUNTIME_OUTPUT_DIRECTORY}/enclave.so")