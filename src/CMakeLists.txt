# 添加各个子模块
add_subdirectory(common)
add_subdirectory(client)
add_subdirectory(server)

# 添加主程序
add_executable(filetransfer main.cpp)

# 链接库
target_link_libraries(filetransfer
    PRIVATE
        client_core
        server_core
        common_protocol
        common_network
        common_utils
) 