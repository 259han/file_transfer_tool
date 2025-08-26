# 添加工具库
add_library(common_utils
    logging/logger.cpp
    config/config_manager.cpp
    crypto/encryption.cpp
    auth/user_manager.cpp
    threading/thread_pool.cpp
)

# 设置包含目录
target_include_directories(common_utils
    PUBLIC
        ${CMAKE_SOURCE_DIR}/include
    PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}
)

# 添加依赖
target_link_libraries(common_utils
    PRIVATE
        OpenSSL::Crypto
        Threads::Threads
) 