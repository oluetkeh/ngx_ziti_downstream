cmake_minimum_required(VERSION 3.14)
project(ngx_ziti_downstream
        VERSION 0.1)

set(ZITI_SDK_DIR /Users/oluetkeh/Developer/openziti/ziti-sdk-c)
link_directories(${ZITI_SDK_DIR}/build/library)

add_executable(ngx_ziti_downstream ../src/ngx_ziti_downstream.c)
target_link_libraries(ngx_ziti_downstream PUBLIC ziti)
target_include_directories(ngx_ziti_downstream PUBLIC
                           "${PROJECT_BINARY_DIR}"
                           "${ZITI_SDK_DIR}/includes"
                           "${ZITI_SDK_DIR}/build/_deps/libuv-src/include"
                           "${ZITI_SDK_DIR}/build/_deps/uv-mbed-src/include"
                           "${ZITI_SDK_DIR}/build/library"
                           )
