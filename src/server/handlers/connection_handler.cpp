#include "connection_handler.h"
#include "../../common/utils/logging/logger.h"
#include <thread>

namespace ft {
namespace server {

ConnectionHandler::ConnectionHandler(std::unique_ptr<network::TcpSocket> socket)
    : socket_(std::move(socket)),
      thread_(),
      running_(false),
      event_callback_(nullptr) {
}

ConnectionHandler::~ConnectionHandler() {
    stop();
}

void ConnectionHandler::start() {
    if (running_) {
        return;
    }
    
    running_ = true;
    thread_ = std::thread(&ConnectionHandler::receive_thread, this);
    
    // 触发连接事件
    if (event_callback_) {
        event_callback_(ConnectionEvent::CONNECTED, nullptr, 0);
    }
}

void ConnectionHandler::stop() {
    if (!running_) {
        return;
    }
    
    running_ = false;
    
    if (socket_) {
        socket_->close();
    }
    
    if (thread_.joinable()) {
        thread_.join();
    }
    
    // 触发断开连接事件
    if (event_callback_) {
        event_callback_(ConnectionEvent::DISCONNECTED, nullptr, 0);
    }
}

bool ConnectionHandler::send(const void* data, size_t len) {
    if (!socket_ || !socket_->is_connected() || !data || len == 0) {
        return false;
    }
    
    network::SocketError err = socket_->send_all(data, len);
    if (err != network::SocketError::SUCCESS) {
        LOG_ERROR("Failed to send data: %d", static_cast<int>(err));
        
        // 触发错误事件
        if (event_callback_) {
            std::string error_msg = "Send error: " + std::to_string(static_cast<int>(err));
            event_callback_(ConnectionEvent::ERROR, error_msg.data(), error_msg.size());
        }
        
        return false;
    }
    
    return true;
}

std::string ConnectionHandler::get_client_address() const {
    if (!socket_) {
        return "unknown";
    }
    
    return socket_->get_remote_address() + ":" + std::to_string(socket_->get_remote_port());
}

bool ConnectionHandler::is_connected() const {
    return socket_ && socket_->is_connected();
}

void ConnectionHandler::set_event_callback(std::function<void(ConnectionEvent, const void*, size_t)> callback) {
    event_callback_ = callback;
}

void ConnectionHandler::receive_thread() {
    const size_t buffer_size = 4096;
    std::vector<uint8_t> buffer(buffer_size);
    
    while (running_ && socket_->is_connected()) {
        // 接收数据
        size_t received = 0;
        network::SocketError err = socket_->recv(buffer.data(), buffer.size(), received);
        
        if (err != network::SocketError::SUCCESS) {
            if (err == network::SocketError::CLOSED) {
                LOG_INFO("Connection closed by peer: %s", get_client_address().c_str());
            } else {
                LOG_ERROR("Failed to receive data: %d", static_cast<int>(err));
                
                // 触发错误事件
                if (event_callback_) {
                    std::string error_msg = "Receive error: " + std::to_string(static_cast<int>(err));
                    event_callback_(ConnectionEvent::ERROR, error_msg.data(), error_msg.size());
                }
            }
            
            break;
        }
        
        if (received > 0) {
            // 触发数据接收事件
            if (event_callback_) {
                event_callback_(ConnectionEvent::DATA_RECEIVED, buffer.data(), received);
            }
        }
    }
    
    // 关闭连接
    socket_->close();
    
    // 触发断开连接事件
    if (event_callback_ && running_) {
        event_callback_(ConnectionEvent::DISCONNECTED, nullptr, 0);
    }
}

} // namespace server
} // namespace ft 