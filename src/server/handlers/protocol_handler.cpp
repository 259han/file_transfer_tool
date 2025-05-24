#include "protocol_handler.h"
#include "../core/client_session.h"
#include "../../common/protocol/protocol.h"

namespace ft {
namespace server {

ProtocolHandler::ProtocolHandler(ClientSession& session)
    : session_(session) {
}

bool ProtocolHandler::send_error_response(const std::string& error_message) {
    LOG_ERROR("Session %zu: %s", get_session_id(), error_message.c_str());
    
    // 创建错误响应
    protocol::Message error_response(protocol::OperationType::ERROR);
    error_response.set_payload(error_message.data(), error_message.size());
    
    std::vector<uint8_t> response_buffer;
    if (!error_response.encode(response_buffer)) {
        LOG_ERROR("Session %zu: Failed to encode error response", get_session_id());
        return false;
    }
    
    try {
        network::SocketError err = session_.get_socket().send_all(response_buffer.data(), response_buffer.size());
        if (err != network::SocketError::SUCCESS) {
            LOG_ERROR("Session %zu: Failed to send error response: %d", 
                     get_session_id(), static_cast<int>(err));
            return false;
        }
        LOG_DEBUG("Session %zu: Sent error response: %s", get_session_id(), error_message.c_str());
        return true;
    } catch (const std::exception& e) {
        LOG_ERROR("Session %zu: Exception while sending error response: %s", 
                 get_session_id(), e.what());
        return false;
    }
}

size_t ProtocolHandler::get_session_id() const {
    return session_.get_session_id();
}

network::TcpSocket& ProtocolHandler::get_socket() {
    return session_.get_socket();
}

bool ProtocolHandler::is_encryption_enabled() const {
    return session_.is_encryption_enabled();
}

bool ProtocolHandler::is_key_exchange_completed() const {
    return session_.is_key_exchange_completed();
}

std::vector<uint8_t> ProtocolHandler::encrypt_data(const std::vector<uint8_t>& data) {
    return session_.encrypt_data(data);
}

std::vector<uint8_t> ProtocolHandler::decrypt_data(const std::vector<uint8_t>& data) {
    return session_.decrypt_data(data);
}

} // namespace server
} // namespace ft 