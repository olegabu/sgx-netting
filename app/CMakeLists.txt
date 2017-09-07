set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} ${SGX_COMMON_CFLAGS} -fPIC -Wno-attributes")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} ${CMAKE_C_FLAGS}")

include_directories(
        $(CMAKE_CURRENT_SOURCE_DIR)
        ${SGX_SDK}/include
        .
)

link_directories(.)
link_libraries(c stdc++ ssl crypto enclave pthread -L${SGX_LIBRARY_PATH} ${SGX_URTS_LIB} ${SGX_USVC_LIB})

add_executable(app
        app.cpp ocall.cpp
        ../common/serial_trades.cpp ../common/serial_trades.h
        ../enclave/enclave_u.c ../common/util.h ../common/buffer.h crypto.cpp crypto.h)

add_custom_command(TARGET app
        POST_BUILD
        COMMAND cp trades.txt ${CMAKE_BINARY_DIR}/bin/
        WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
        COMMENT "cp trades.txt")
