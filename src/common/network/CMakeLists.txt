# 添加网络库
add_library(common_network
    socket/tcp_socket.cpp
    connection/connection_pool.cpp
    async/event_loop.cpp
)

# 设置包含目录
target_include_directories(common_network
    PUBLIC
        ${CMAKE_SOURCE_DIR}/include
    PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}
)

# 添加依赖
target_link_libraries(common_network
    PRIVATE
        Threads::Threads
) 