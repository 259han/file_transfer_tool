#include "authentication_handler.h"
#include "../../common/utils/logging/logger.h"
#include <openssl/rand.h>
#include <iomanip>
#include <sstream>

namespace ft {
namespace server {

// 静态成员定义
const int AuthenticationHandler::SESSION_TIMEOUT_MINUTES;

AuthenticationHandler::AuthenticationHandler() 
    : user_manager_(utils::UserManager::instance()) {
}

AuthenticationHandler::~AuthenticationHandler() {
    // 清理所有会话
    std::lock_guard<std::mutex> lock(sessions_mutex_);
    sessions_.clear();
}

bool AuthenticationHandler::handle_authentication_request(
    std::shared_ptr<network::TcpSocket> socket, 
    const protocol::AuthenticationMessage& auth_msg) {
    
    if (!socket) {
        LOG_ERROR("Invalid socket for authentication request");
        return false;
    }
    
    LOG_INFO("Processing authentication request, type: %d", static_cast<int>(auth_msg.get_auth_type()));
    
    switch (auth_msg.get_auth_type()) {
        case protocol::AuthenticationType::USERNAME_PASSWORD:
            return handle_username_password_auth(socket, auth_msg);
            
        case protocol::AuthenticationType::API_KEY:
            return handle_api_key_auth(socket, auth_msg);
            
        default:
            LOG_WARNING("Unsupported authentication type: %d", static_cast<int>(auth_msg.get_auth_type()));
            return send_auth_response(socket, protocol::AuthenticationResult::UNSUPPORTED_TYPE);
    }
}

bool AuthenticationHandler::handle_username_password_auth(
    std::shared_ptr<network::TcpSocket> socket,
    const protocol::AuthenticationMessage& auth_msg) {
    
    const std::string& username = auth_msg.get_username();
    const std::string& password = auth_msg.get_password_hash(); // 注意：尽管字段名为password_hash，实际传输的是原始密码
    
    if (username.empty() || password.empty()) {
        LOG_WARNING("Invalid username/password in authentication request");
        return send_auth_response(socket, protocol::AuthenticationResult::INVALID_CREDENTIALS);
    }
    
    // 使用UserManager验证用户名和原始密码
    protocol::AuthenticationResult result = user_manager_.authenticate_user(username, password);
    
    if (result == protocol::AuthenticationResult::SUCCESS) {
        // 创建会话
        uint8_t permissions = user_manager_.get_user_permissions(username);
        std::string session_id = create_session(username, "user", permissions);
        
        LOG_INFO("User authentication successful: %s, session: %.8s", username.c_str(), session_id.c_str());
        return send_auth_response(socket, result, session_id, permissions);
    } else {
        LOG_WARNING("User authentication failed: %s, result: %d", username.c_str(), static_cast<int>(result));
        return send_auth_response(socket, result);
    }
}

bool AuthenticationHandler::handle_api_key_auth(
    std::shared_ptr<network::TcpSocket> socket,
    const protocol::AuthenticationMessage& auth_msg) {
    
    const std::string& api_key = auth_msg.get_api_key();
    
    if (api_key.empty()) {
        LOG_WARNING("Empty API key in authentication request");
        return send_auth_response(socket, protocol::AuthenticationResult::INVALID_CREDENTIALS);
    }
    
    protocol::AuthenticationResult result = user_manager_.authenticate_api_key(api_key);
    
    if (result == protocol::AuthenticationResult::SUCCESS) {
        // 创建会话
        uint8_t permissions = user_manager_.get_api_key_permissions(api_key);
        std::string session_id = create_session(api_key, "apikey", permissions);
        
        LOG_INFO("API key authentication successful: %.12s..., session: %.8s", 
                 api_key.c_str(), session_id.c_str());
        return send_auth_response(socket, result, session_id, permissions);
    } else {
        LOG_WARNING("API key authentication failed: %.12s..., result: %d", 
                   api_key.c_str(), static_cast<int>(result));
        return send_auth_response(socket, result);
    }
}

bool AuthenticationHandler::send_auth_response(
    std::shared_ptr<network::TcpSocket> socket,
    protocol::AuthenticationResult result,
    const std::string& session_id,
    uint8_t permissions) {
    
    protocol::AuthenticationMessage response(protocol::AuthenticationPhase::AUTH_RESPONSE);
    response.set_auth_result(result);
    response.set_permissions(permissions);
    
    // 如果认证成功，设置会话ID（通过用户名字段传递）
    if (result == protocol::AuthenticationResult::SUCCESS && !session_id.empty()) {
        response.set_username(session_id);
    }
    
    std::vector<uint8_t> buffer;
    if (!response.encode(buffer)) {
        LOG_ERROR("Failed to encode authentication response");
        return false;
    }
    
    size_t sent_len = 0;
    network::SocketError error = socket->send(buffer.data(), buffer.size(), sent_len);
    if (error != network::SocketError::SUCCESS || sent_len != buffer.size()) {
        LOG_ERROR("Failed to send authentication response, error: %d, sent: %zu/%zu", 
                 static_cast<int>(error), sent_len, buffer.size());
        return false;
    }
    
    return true;
}

std::string AuthenticationHandler::generate_session_id() {
    unsigned char session_bytes[16];
    if (RAND_bytes(session_bytes, sizeof(session_bytes)) != 1) {
        return "";
    }
    
    std::stringstream ss;
    for (int i = 0; i < 16; ++i) {
        ss << std::hex << std::setw(2) << std::setfill('0') << (int)session_bytes[i];
    }
    return ss.str();
}

std::string AuthenticationHandler::create_session(
    const std::string& username, 
    const std::string& auth_type, 
    uint8_t permissions) {
    
    std::string session_id = generate_session_id();
    if (session_id.empty()) {
        return "";
    }
    
    std::lock_guard<std::mutex> lock(sessions_mutex_);
    
    SessionInfo session_info;
    session_info.username = username;
    session_info.auth_type = auth_type;
    session_info.permissions = permissions;
    session_info.created_at = std::chrono::system_clock::now();
    session_info.last_activity = session_info.created_at;
    
    sessions_[session_id] = session_info;
    
    return session_id;
}

bool AuthenticationHandler::is_session_authenticated(const std::string& session_id) const {
    std::lock_guard<std::mutex> lock(sessions_mutex_);
    
    auto it = sessions_.find(session_id);
    if (it == sessions_.end()) {
        return false;
    }
    
    // 检查会话是否过期
    auto now = std::chrono::system_clock::now();
    auto elapsed = std::chrono::duration_cast<std::chrono::minutes>(now - it->second.last_activity);
    
    return elapsed.count() < SESSION_TIMEOUT_MINUTES;
}

std::string AuthenticationHandler::get_session_username(const std::string& session_id) const {
    std::lock_guard<std::mutex> lock(sessions_mutex_);
    
    auto it = sessions_.find(session_id);
    if (it == sessions_.end()) {
        return "";
    }
    
    // 检查会话是否过期
    auto now = std::chrono::system_clock::now();
    auto elapsed = std::chrono::duration_cast<std::chrono::minutes>(now - it->second.last_activity);
    
    if (elapsed.count() >= SESSION_TIMEOUT_MINUTES) {
        return "";
    }
    
    return it->second.username;
}

uint8_t AuthenticationHandler::get_session_permissions(const std::string& session_id) const {
    std::lock_guard<std::mutex> lock(sessions_mutex_);
    
    auto it = sessions_.find(session_id);
    if (it == sessions_.end()) {
        return 0;
    }
    
    // 检查会话是否过期
    auto now = std::chrono::system_clock::now();
    auto elapsed = std::chrono::duration_cast<std::chrono::minutes>(now - it->second.last_activity);
    
    if (elapsed.count() >= SESSION_TIMEOUT_MINUTES) {
        return 0;
    }
    
    return it->second.permissions;
}

bool AuthenticationHandler::has_session_permission(
    const std::string& session_id, 
    protocol::UserPermission permission) const {
    
    uint8_t permissions = get_session_permissions(session_id);
    return (permissions & static_cast<uint8_t>(permission)) != 0;
}

void AuthenticationHandler::logout_session(const std::string& session_id) {
    std::lock_guard<std::mutex> lock(sessions_mutex_);
    
    auto it = sessions_.find(session_id);
    if (it != sessions_.end()) {
        LOG_INFO("Session logged out: %.8s", session_id.c_str());
        sessions_.erase(it);
    }
}

void AuthenticationHandler::cleanup_expired_sessions() {
    std::lock_guard<std::mutex> lock(sessions_mutex_);
    
    auto now = std::chrono::system_clock::now();
    auto it = sessions_.begin();
    int removed_count = 0;
    
    while (it != sessions_.end()) {
        auto elapsed = std::chrono::duration_cast<std::chrono::minutes>(now - it->second.last_activity);
        
        if (elapsed.count() >= SESSION_TIMEOUT_MINUTES) {
            it = sessions_.erase(it);
            removed_count++;
        } else {
            ++it;
        }
    }
    
    if (removed_count > 0) {
        LOG_INFO("Cleaned up %d expired sessions", removed_count);
    }
}

} // namespace server
} // namespace ft 