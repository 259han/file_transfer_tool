#include "socket_error.h"

namespace ft {
namespace network {

const char* socket_error_to_string(SocketError error) {
    switch (error) {
        case SocketError::SUCCESS:
            return "Success";
        case SocketError::SOCKET_CREATE_FAILED:
            return "Socket creation failed";
        case SocketError::BIND_FAILED:
            return "Socket bind failed";
        case SocketError::LISTEN_FAILED:
            return "Socket listen failed";
        case SocketError::CONNECT_FAILED:
            return "Socket connect failed";
        case SocketError::ACCEPT_FAILED:
            return "Socket accept failed";
        case SocketError::SEND_FAILED:
            return "Socket send failed";
        case SocketError::RECV_FAILED:
            return "Socket receive failed";
        case SocketError::TIMEOUT:
            return "Operation timeout";
        case SocketError::CLOSED:
            return "Connection closed";
        case SocketError::INVALID_STATE:
            return "Invalid socket state";
        case SocketError::INVALID_ARGUMENT:
            return "Invalid argument";
        case SocketError::NETWORK_ERROR:
            return "Network error";
        case SocketError::MEMORY_ERROR:
            return "Memory error";
        case SocketError::UNKNOWN_ERROR:
        default:
            return "Unknown error";
    }
}

} // namespace network
} // namespace ft
