# 添加客户端核心库
add_library(client_core
    core/client_core.cpp
    handlers/upload_handler.cpp
    handlers/download_handler.cpp
    utils/progress_tracker.cpp
)

# 设置包含目录
target_include_directories(client_core
    PUBLIC
        ${CMAKE_SOURCE_DIR}/include
    PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}
)

# 添加依赖
target_link_libraries(client_core
    PRIVATE
        common_protocol
        common_network
        common_utils
)

# 创建可执行文件
add_executable(file_transfer_client client.cpp)

# 设置包含目录
target_include_directories(file_transfer_client
    PRIVATE
        ${CMAKE_SOURCE_DIR}/include
        ${CMAKE_CURRENT_SOURCE_DIR}
)

# 添加依赖
target_link_libraries(file_transfer_client
    PRIVATE
        client_core
) 