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