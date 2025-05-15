# 添加服务器核心库
add_library(server_core
    core/server_core.cpp
    handlers/connection_handler.cpp
    handlers/file_handler.cpp
    session/session_manager.cpp
)

# 设置包含目录
target_include_directories(server_core
    PUBLIC
        ${CMAKE_SOURCE_DIR}/include
    PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}
)

# 添加依赖
target_link_libraries(server_core
    PRIVATE
        common_protocol
        common_network
        common_utils
        Threads::Threads
)

# 创建可执行文件
add_executable(file_transfer_server server.cpp)

# 设置包含目录
target_include_directories(file_transfer_server
    PRIVATE
        ${CMAKE_SOURCE_DIR}/include
        ${CMAKE_CURRENT_SOURCE_DIR}
)

# 添加依赖
target_link_libraries(file_transfer_server
    PRIVATE
        server_core
        Threads::Threads
) 