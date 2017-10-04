set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} ${SGX_COMMON_CFLAGS} -fPIC -Wno-attributes")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} ${CMAKE_C_FLAGS}")

include_directories(
        $(CMAKE_CURRENT_SOURCE_DIR)
        ${SGX_SDK}/include
        .
)

link_directories(.)
link_libraries(c stdc++ ssl crypto enclave pthread -L${SGX_LIBRARY_PATH} ${SGX_URTS_LIB} ${SGX_USVC_LIB})

set(SOURCES app.h app.cpp
        ../common/serial_trades.h ../common/serial_trades.cpp
        ../common/util.h ../common/buffer.h
        ../common/crypto.h crypto.cpp
        ../common/NotionalMatrix.h
        ../enclave/enclave_u.c ocall.cpp)

add_executable(app
        main.cpp ${SOURCES})

file(COPY trades.txt
        DESTINATION ${CMAKE_RUNTIME_OUTPUT_DIRECTORY})
