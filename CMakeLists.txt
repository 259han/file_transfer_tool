cmake_minimum_required(VERSION 3.15)
project(file_transfer_tool VERSION 1.0)

# 设置C++标准
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# 添加编译选项
add_compile_options(-Wall -Wextra -Wpedantic)

# 设置输出目录
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)

# 添加测试选项
option(BUILD_TESTS "Build test programs" ON)

# 添加异步服务器选项
option(BUILD_ASYNC_SERVER "Build async server version" ON)

# 查找外部依赖
find_package(OpenSSL REQUIRED)
if(NOT OpenSSL_FOUND)
    message(STATUS "OpenSSL not found. Trying to find manually...")
    # 尝试手动查找OpenSSL
    set(OPENSSL_ROOT_DIR /usr/local/ssl)
    set(OPENSSL_INCLUDE_DIR /usr/include/openssl)
    set(OPENSSL_CRYPTO_LIBRARY /usr/lib/x86_64-linux-gnu/libcrypto.so)
    set(OPENSSL_SSL_LIBRARY /usr/lib/x86_64-linux-gnu/libssl.so)
endif()

find_package(ZLIB REQUIRED)
find_package(Threads REQUIRED)

# 查找jsoncpp库
find_package(PkgConfig REQUIRED)
pkg_check_modules(JSONCPP jsoncpp)
if(NOT JSONCPP_FOUND)
    message(STATUS "jsoncpp not found via pkg-config. Trying to find manually...")
    # 修正jsoncpp的包含路径
    set(JSONCPP_INCLUDE_DIRS "/usr/include/jsoncpp")
    find_library(JSONCPP_LIBRARIES
            NAMES jsoncpp
            PATHS /usr/lib /usr/local/lib)
    if(JSONCPP_INCLUDE_DIRS AND JSONCPP_LIBRARIES)
        set(JSONCPP_FOUND TRUE)
        message(STATUS "Found jsoncpp: ${JSONCPP_LIBRARIES}")
    else()
        message(FATAL_ERROR "jsoncpp library not found. Please install jsoncpp development package.")
    endif()
endif()

# 添加子目录
add_subdirectory(src)

# 如果构建测试，添加tests子目录
if(BUILD_TESTS)
    message(STATUS "Building tests")
    add_subdirectory(tests)
endif()

# 如果构建异步服务器，添加异步相关目标
if(BUILD_ASYNC_SERVER)
    message(STATUS "Building async server")
    
    # 异步网络库
    add_library(async_network
        src/common/network/async/event_loop.cpp
        src/common/utils/threading/thread_pool.cpp
    )
    
    # 异步服务器核心库
    add_library(async_server_core
        src/server/core/async_server_core.cpp
    )
    
    # 异步服务器链接依赖
    target_link_libraries(async_server_core
        PRIVATE
            async_network
            server_core
            common_protocol
            common_network
            common_utils
            Threads::Threads
    )
    
    # 异步服务器可执行文件
    add_executable(async_server_main
        src/server/async_server_main.cpp
    )
    
    target_link_libraries(async_server_main
        PRIVATE
            async_server_core
    )
    
    # 性能测试工具
    add_executable(performance_test
        tools/performance_test.cpp
    )
    
    target_link_libraries(performance_test
        PRIVATE
            Threads::Threads
    )
    
    # 设置平台特定选项
    if(WIN32)
        target_link_libraries(performance_test PRIVATE ws2_32)
    endif()
    
endif() 