set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} ${SGX_COMMON_CFLAGS} -fPIC -Wno-attributes")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} ${CMAKE_C_FLAGS}")

include_directories(
        $(CMAKE_CURRENT_SOURCE_DIR)
        ${SGX_SDK}/include
        .
)

set(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} -O0")
set(CMAKE_C_FLAGS_DEBUG "${CMAKE_C_FLAGS_DEBUG} -O0")

link_directories(.)
link_libraries(c stdc++ ssl crypto enclave pthread pistache -L${CMAKE_CURRENT_SOURCE_DIR}/../lib -L${SGX_LIBRARY_PATH} ${SGX_URTS_LIB} ${SGX_USVC_LIB})

set(SOURCES app.h app.cpp
        ../common/serial_trades.h ../common/serial_trades.cpp
        ../common/util.h ../common/buffer.h
        ../common/crypto.h crypto.cpp
        ../common/NotionalMatrix.h
        ../enclave/enclave_u.c ocall.cpp)

add_executable(test_app
        test_main.cpp ${SOURCES})

add_executable(rest_sgx
        rest_main.cpp ${SOURCES})

add_executable(test_rest
        test_rest.cpp ${SOURCES})

add_dependencies(test_rest rest_sgx)
add_test(NAME App COMMAND $<TARGET_FILE:test_app>
        WORKING_DIRECTORY ${CMAKE_RUNTIME_OUTPUT_DIRECTORY}/)
add_test(NAME Rest COMMAND $<TARGET_FILE:test_rest>
        WORKING_DIRECTORY ${CMAKE_RUNTIME_OUTPUT_DIRECTORY}/)

file(COPY trades.txt
        DESTINATION ${CMAKE_RUNTIME_OUTPUT_DIRECTORY})