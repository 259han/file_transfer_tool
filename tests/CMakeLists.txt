cmake_minimum_required(VERSION 3.10)

# 设置输出目录与主项目一致
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)

# 添加GoogleTest
include(FetchContent)
FetchContent_Declare(
  googletest
  GIT_REPOSITORY https://github.com/google/googletest.git
  GIT_TAG release-1.11.0
)
FetchContent_MakeAvailable(googletest)

# 单元测试
add_executable(crypto_test 
  unit/crypto_test.cpp
)
target_link_libraries(crypto_test 
  gtest_main 
  common_protocol
  common_utils
  OpenSSL::Crypto
)
target_include_directories(crypto_test PRIVATE 
  ${CMAKE_SOURCE_DIR}/src
  ${CMAKE_SOURCE_DIR}/include
)

# 集成测试
add_executable(client_encryption_test 
  integration/client_encryption_test.cpp
)
target_link_libraries(client_encryption_test 
  gtest_main 
  client_core
  common_protocol
  common_utils
  common_network
  OpenSSL::Crypto
  Threads::Threads
)
target_include_directories(client_encryption_test PRIVATE 
  ${CMAKE_SOURCE_DIR}/src
  ${CMAKE_SOURCE_DIR}/include
)

# 端到端测试
add_executable(encryption_e2e_test 
  integration/encryption_e2e_test.cpp
)
target_link_libraries(encryption_e2e_test 
  gtest_main 
  client_core
  server_core
  common_protocol
  common_utils
  common_network
  OpenSSL::Crypto
  Threads::Threads
)
target_include_directories(encryption_e2e_test PRIVATE 
  ${CMAKE_SOURCE_DIR}/src
  ${CMAKE_SOURCE_DIR}/include
)

# 添加测试
include(GoogleTest)
gtest_discover_tests(crypto_test)
gtest_discover_tests(client_encryption_test)
gtest_discover_tests(encryption_e2e_test)