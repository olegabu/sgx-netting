set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} ${SGX_COMMON_CFLAGS} -fPIC -Wno-attributes")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} ${CMAKE_C_FLAGS} -std=c++11")

include_directories(
        $(CMAKE_CURRENT_SOURCE_DIR)
        ${SGX_SDK}/include
        .
)

link_directories(.)
link_libraries(c stdc++ ssl crypto enclave -L${SGX_LIBRARY_PATH} ${SGX_URTS_LIB} ${SGX_USVC_LIB})

add_executable(app
        app.cpp ocall.cpp
        ../common/serial_trades.cpp ../common/serial_trades.h
        ../enclave/enclave_u.c ../common/util.h ../common/buffer.h crypto.cpp crypto.h)