# 添加协议库
add_library(common_protocol
    core/protocol_header.cpp
    messages/upload_message.cpp
    messages/download_message.cpp
    messages/key_exchange_message.cpp
    protocol.cpp
)

# 设置包含目录
target_include_directories(common_protocol
    PUBLIC
        ${CMAKE_SOURCE_DIR}/include
    PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}
)

# 添加依赖
target_link_libraries(common_protocol
    PRIVATE
        OpenSSL::Crypto
        ZLIB::ZLIB
) 