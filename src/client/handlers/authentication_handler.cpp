#include "authentication_handler.h"
#include "../../common/protocol/protocol.h"
#include "../../common/utils/logging/logger.h"
#include <chrono>
#include <thread>
#include <cstring>

namespace ft {
namespace client {

ClientAuthenticationHandler::ClientAuthenticationHandler()
    : authenticated_(false),
      session_id_(),
      username_(),
      permissions_(0) {
}

ClientAuthenticationHandler::~ClientAuthenticationHandler() {
    clear_authentication();
}

AuthenticationResult ClientAuthenticationHandler::authenticate_user(network::TcpSocket& socket,
                                                                   const std::string& username,
                                                                   const std::string& password) {
    LOG_INFO("Attempting to authenticate user: %s", username.c_str());
    
    // 创建认证请求消息
    protocol::AuthenticationMessage auth_request(protocol::AuthenticationPhase::AUTH_REQUEST);
    auth_request.set_auth_type(protocol::AuthenticationType::USERNAME_PASSWORD);
    auth_request.set_username_password_auth(username, password);
    
    // 发送认证请求
    if (!send_auth_request(socket, auth_request)) {
        AuthenticationResult result;
        result.error_message = "Failed to send authentication request";
        LOG_ERROR("Failed to send authentication request for user: %s", username.c_str());
        return result;
    }
    
    LOG_DEBUG("Authentication request sent for user: %s", username.c_str());
    
    // 接收认证响应
    AuthenticationResult result = receive_auth_response(socket);
    
    if (result.success) {
        // 更新内部状态
        authenticated_ = true;
        session_id_ = result.session_id;
        username_ = result.username;
        permissions_ = result.permissions;
        
        LOG_INFO("User %s authenticated successfully with permissions: %d", 
                 username.c_str(), permissions_);
    } else {
        LOG_WARNING("Authentication failed for user %s: %s", 
                   username.c_str(), result.error_message.c_str());
    }
    
    return result;
}

AuthenticationResult ClientAuthenticationHandler::authenticate_api_key(network::TcpSocket& socket,
                                                                       const std::string& api_key) {
    LOG_INFO("Attempting to authenticate with API key: %s...", api_key.substr(0, 8).c_str());
    
    // 创建认证请求消息
    protocol::AuthenticationMessage auth_request(protocol::AuthenticationPhase::AUTH_REQUEST);
    auth_request.set_auth_type(protocol::AuthenticationType::API_KEY);
    auth_request.set_api_key_auth(api_key);
    
    // 发送认证请求
    if (!send_auth_request(socket, auth_request)) {
        AuthenticationResult result;
        result.error_message = "Failed to send API key authentication request";
        LOG_ERROR("Failed to send API key authentication request");
        return result;
    }
    
    LOG_DEBUG("API key authentication request sent");
    
    // 接收认证响应
    AuthenticationResult result = receive_auth_response(socket);
    
    if (result.success) {
        // 更新内部状态
        authenticated_ = true;
        session_id_ = result.session_id;
        username_ = result.username;
        permissions_ = result.permissions;
        
        LOG_INFO("API key authenticated successfully for user %s with permissions: %d", 
                 username_.c_str(), permissions_);
    } else {
        LOG_WARNING("API key authentication failed: %s", result.error_message.c_str());
    }
    
    return result;
}

bool ClientAuthenticationHandler::is_authenticated() const {
    return authenticated_;
}

const std::string& ClientAuthenticationHandler::get_session_id() const {
    return session_id_;
}

const std::string& ClientAuthenticationHandler::get_username() const {
    return username_;
}

uint8_t ClientAuthenticationHandler::get_permissions() const {
    return permissions_;
}

bool ClientAuthenticationHandler::has_permission(uint8_t permission) const {
    return authenticated_ && (permissions_ & permission) != 0;
}

void ClientAuthenticationHandler::clear_authentication() {
    authenticated_ = false;
    session_id_.clear();
    username_.clear();
    permissions_ = 0;
    
    LOG_DEBUG("Authentication state cleared");
}

bool ClientAuthenticationHandler::send_auth_request(network::TcpSocket& socket, 
                                                   const protocol::AuthenticationMessage& auth_msg) {
    // 创建认证消息的副本以便编码
    protocol::AuthenticationMessage msg_copy = auth_msg;
    
    // 编码认证消息
    std::vector<uint8_t> msg_buffer;
    if (!msg_copy.encode(msg_buffer)) {
        LOG_ERROR("Failed to encode authentication message");
        return false;
    }
    
    LOG_DEBUG("Sending authentication request, size: %zu bytes", msg_buffer.size());
    
    // 发送消息
    network::SocketError err = socket.send_all(msg_buffer.data(), msg_buffer.size());
    if (err != network::SocketError::SUCCESS) {
        LOG_ERROR("Failed to send authentication request: %d", static_cast<int>(err));
        return false;
    }
    
    LOG_DEBUG("Authentication request sent successfully");
    return true;
}

AuthenticationResult ClientAuthenticationHandler::receive_auth_response(network::TcpSocket& socket) {
    AuthenticationResult result;
    
    // 接收响应头
    protocol::ProtocolHeader header;
    network::SocketError err = socket.recv_all(&header, sizeof(header));
    if (err != network::SocketError::SUCCESS) {
        result.error_message = "Failed to receive authentication response header";
        LOG_ERROR("Failed to receive authentication response header: %d", static_cast<int>(err));
        return result;
    }
    
    // 验证响应头
    if (header.magic != protocol::PROTOCOL_MAGIC) {
        result.error_message = "Invalid protocol magic in authentication response";
        uint32_t magic_val = header.magic;
        LOG_ERROR("Invalid protocol magic in authentication response: 0x%08x", magic_val);
        return result;
    }
    
    if (static_cast<protocol::OperationType>(header.type) != protocol::OperationType::AUTHENTICATION) {
        result.error_message = "Invalid operation type in authentication response";
        LOG_ERROR("Invalid operation type in authentication response: %d", header.type);
        return result;
    }
    
    // 接收响应体
    std::vector<uint8_t> response_buffer(sizeof(protocol::ProtocolHeader) + header.length);
    memcpy(response_buffer.data(), &header, sizeof(protocol::ProtocolHeader));
    
    if (header.length > 0) {
        err = socket.recv_all(response_buffer.data() + sizeof(protocol::ProtocolHeader), header.length);
        if (err != network::SocketError::SUCCESS) {
            result.error_message = "Failed to receive authentication response body";
            LOG_ERROR("Failed to receive authentication response body: %d", static_cast<int>(err));
            return result;
        }
    }
    
    LOG_DEBUG("Received authentication response, total size: %zu bytes", response_buffer.size());
    
    // 直接解码认证响应消息，避免重复解码
    protocol::AuthenticationMessage auth_response(protocol::AuthenticationPhase::AUTH_RESPONSE);
    if (!auth_response.decode(response_buffer)) {
        result.error_message = "Failed to decode authentication response";
        LOG_ERROR("Failed to decode authentication response");
        return result;
    }
    
    // 检查响应阶段
    if (auth_response.get_auth_phase() != protocol::AuthenticationPhase::AUTH_RESPONSE) {
        result.error_message = "Invalid authentication phase in response";
        LOG_ERROR("Invalid authentication phase in response: %d", 
                 static_cast<int>(auth_response.get_auth_phase()));
        return result;
    }
    
    // 检查认证结果
    protocol::AuthenticationResult auth_result = auth_response.get_auth_result();
    
    switch (auth_result) {
        case protocol::AuthenticationResult::SUCCESS:
            result.success = true;
            result.session_id = auth_response.get_username() + "_session"; // 临时会话ID生成
            result.username = auth_response.get_username();
            result.permissions = auth_response.get_permissions();
            LOG_INFO("Authentication successful for user: %s", result.username.c_str());
            break;
            
        case protocol::AuthenticationResult::INVALID_CREDENTIALS:
            result.error_message = "Invalid credentials";
            LOG_WARNING("Authentication failed: Invalid credentials");
            break;
            
        case protocol::AuthenticationResult::USER_NOT_FOUND:
            result.error_message = "User not found";
            LOG_WARNING("Authentication failed: User not found");
            break;
            
        case protocol::AuthenticationResult::ACCOUNT_LOCKED:
            result.error_message = "Account locked";
            LOG_WARNING("Authentication failed: Account locked");
            break;
            
        case protocol::AuthenticationResult::SERVER_ERROR:
            result.error_message = "Server error";
            LOG_ERROR("Authentication failed: Server error");
            break;
            
        case protocol::AuthenticationResult::UNSUPPORTED_TYPE:
            result.error_message = "Unsupported authentication type";
            LOG_ERROR("Authentication failed: Unsupported authentication type");
            break;
            
        default:
            result.error_message = "Unknown authentication result";
            LOG_ERROR("Authentication failed: Unknown result code %d", static_cast<int>(auth_result));
            break;
    }
    
    return result;
}

} // namespace client
} // namespace ft 