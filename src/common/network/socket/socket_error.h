#pragma once

namespace ft {
namespace network {

enum class SocketError {
    SUCCESS = 0,
    SOCKET_CREATE_FAILED,
    BIND_FAILED,
    LISTEN_FAILED,
    CONNECT_FAILED,
    ACCEPT_FAILED,
    SEND_FAILED,
    RECV_FAILED,
    TIMEOUT,
    CLOSED,
    CONNECTION_CLOSED = CLOSED,  // 别名，保持兼容性
    INVALID_STATE,
    INVALID_ARGUMENT,
    NETWORK_ERROR,
    MEMORY_ERROR,
    UNKNOWN_ERROR
};

// 将错误码转换为字符串
const char* socket_error_to_string(SocketError error);

} // namespace network
} // namespace ft
