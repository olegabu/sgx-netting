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
        main.cpp app.h app.cpp ocall.cpp
        ../common/serial_trades.cpp ../common/serial_trades.h
         ../common/util.h ../common/buffer.h crypto.cpp crypto.h ../common/NotionalMatrix.h
        ../enclave/enclave_u.h ../enclave/enclave_u.c)



add_custom_command(TARGET app
        POST_BUILD
        COMMAND cp trades.txt ${CMAKE_RUNTIME_OUTPUT_DIRECTORY}
        WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
        COMMENT "cp trades.txt")

# JNI lib

find_package(JNI REQUIRED)
include_directories(${JNI_INCLUDE_DIRS})

add_custom_command(
        OUTPUT ${CMAKE_CURRENT_SOURCE_DIR}/App.h
        DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/App.java
        COMMAND javah App
        WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR})

add_library(app_jni SHARED
        App.h app_jni.h app_jni.cpp app.h app.cpp ocall.cpp
        ../common/serial_trades.cpp ../common/serial_trades.h
        ../common/util.h ../common/buffer.h crypto.cpp crypto.h ../common/NotionalMatrix.h
        ../enclave/enclave_u.h ../enclave/enclave_u.c)

add_dependencies(app_jni enclave)

# JAVA

find_package(Java REQUIRED)
include(UseJava)

set(CMAKE_JAVA_COMPILE_FLAGS "-source" "1.8" "-target" "1.8")

add_jar(App App.java data/Trade.java data/StandardId.java ENTRY_POINT App
        OUTPUT_DIR ${CMAKE_RUNTIME_OUTPUT_DIRECTORY})

get_target_property(_jar_inst App INSTALL_FILES)
install_jar(App ${CMAKE_BINARY_DIR}/bin/)

add_dependencies(App app_jni)