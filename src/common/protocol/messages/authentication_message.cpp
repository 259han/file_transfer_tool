#include "authentication_message.h"
#include "../../utils/crypto/encryption.h"
#include <cstring>

namespace ft {
namespace protocol {

AuthenticationMessage::AuthenticationMessage(AuthenticationPhase phase)
    : Message(OperationType::AUTHENTICATION),
      auth_phase_(phase),
      auth_type_(AuthenticationType::USERNAME_PASSWORD),
      auth_result_(AuthenticationResult::SUCCESS),
      permissions_(0) {
}

AuthenticationMessage::AuthenticationMessage(const Message& msg)
    : Message(msg),
      auth_phase_(AuthenticationPhase::AUTH_REQUEST),
      auth_type_(AuthenticationType::USERNAME_PASSWORD),
      auth_result_(AuthenticationResult::SUCCESS),
      permissions_(0) {
    if (msg.get_operation_type() == OperationType::AUTHENTICATION) {
        decode(msg.get_payload());
    }
}

bool AuthenticationMessage::has_permission(UserPermission permission) const {
    return (permissions_ & static_cast<uint8_t>(permission)) != 0;
}

void AuthenticationMessage::add_permission(UserPermission permission) {
    permissions_ |= static_cast<uint8_t>(permission);
}

void AuthenticationMessage::remove_permission(UserPermission permission) {
    permissions_ &= ~static_cast<uint8_t>(permission);
}

void AuthenticationMessage::set_username_password_auth(const std::string& username, const std::string& password_hash) {
    auth_type_ = AuthenticationType::USERNAME_PASSWORD;
    username_ = username;
    password_hash_ = password_hash;
    api_key_.clear();
}

void AuthenticationMessage::set_api_key_auth(const std::string& api_key) {
    auth_type_ = AuthenticationType::API_KEY;
    api_key_ = api_key;
    username_.clear();
    password_hash_.clear();
}

bool AuthenticationMessage::encode(std::vector<uint8_t>& buffer) {
    // 计算负载大小
    size_t payload_size = sizeof(uint8_t) * 4; // auth_phase, auth_type, auth_result, permissions
    
    // 字符串长度
    payload_size += sizeof(uint32_t) + username_.size();
    payload_size += sizeof(uint32_t) + password_hash_.size();
    payload_size += sizeof(uint32_t) + api_key_.size();
    
    // 创建负载
    std::vector<uint8_t> payload(payload_size);
    size_t offset = 0;
    
    // 写入认证阶段
    payload[offset++] = static_cast<uint8_t>(auth_phase_);
    
    // 写入认证类型
    payload[offset++] = static_cast<uint8_t>(auth_type_);
    
    // 写入认证结果
    payload[offset++] = static_cast<uint8_t>(auth_result_);
    
    // 写入权限
    payload[offset++] = permissions_;
    
    // 写入用户名
    uint32_t username_len = static_cast<uint32_t>(username_.size());
    std::memcpy(payload.data() + offset, &username_len, sizeof(uint32_t));
    offset += sizeof(uint32_t);
    if (username_len > 0) {
        std::memcpy(payload.data() + offset, username_.data(), username_len);
        offset += username_len;
    }
    
    // 写入密码哈希
    uint32_t password_hash_len = static_cast<uint32_t>(password_hash_.size());
    std::memcpy(payload.data() + offset, &password_hash_len, sizeof(uint32_t));
    offset += sizeof(uint32_t);
    if (password_hash_len > 0) {
        std::memcpy(payload.data() + offset, password_hash_.data(), password_hash_len);
        offset += password_hash_len;
    }
    
    // 写入API密钥
    uint32_t api_key_len = static_cast<uint32_t>(api_key_.size());
    std::memcpy(payload.data() + offset, &api_key_len, sizeof(uint32_t));
    offset += sizeof(uint32_t);
    if (api_key_len > 0) {
        std::memcpy(payload.data() + offset, api_key_.data(), api_key_len);
        offset += api_key_len;
    }
    
    // 设置负载
    set_payload(payload.data(), payload.size());
    
    // 编码消息
    return Message::encode(buffer);
}

bool AuthenticationMessage::decode(const std::vector<uint8_t>& buffer) {
    // 首先解码基本消息
    if (!Message::decode(buffer)) {
        return false;
    }
    
    // 检查操作类型
    if (get_operation_type() != OperationType::AUTHENTICATION) {
        return false;
    }
    
    const std::vector<uint8_t>& payload = get_payload();
    if (payload.size() < 4) {
        return false;
    }
    
    size_t offset = 0;
    
    // 读取认证阶段
    auth_phase_ = static_cast<AuthenticationPhase>(payload[offset++]);
    
    // 读取认证类型
    auth_type_ = static_cast<AuthenticationType>(payload[offset++]);
    
    // 读取认证结果
    auth_result_ = static_cast<AuthenticationResult>(payload[offset++]);
    
    // 读取权限
    permissions_ = payload[offset++];
    
    // 读取用户名
    if (offset + sizeof(uint32_t) > payload.size()) {
        return false;
    }
    uint32_t username_len;
    std::memcpy(&username_len, payload.data() + offset, sizeof(uint32_t));
    offset += sizeof(uint32_t);
    
    if (offset + username_len > payload.size()) {
        return false;
    }
    username_.assign(reinterpret_cast<const char*>(payload.data() + offset), username_len);
    offset += username_len;
    
    // 读取密码哈希
    if (offset + sizeof(uint32_t) > payload.size()) {
        return false;
    }
    uint32_t password_hash_len;
    std::memcpy(&password_hash_len, payload.data() + offset, sizeof(uint32_t));
    offset += sizeof(uint32_t);
    
    if (offset + password_hash_len > payload.size()) {
        return false;
    }
    password_hash_.assign(reinterpret_cast<const char*>(payload.data() + offset), password_hash_len);
    offset += password_hash_len;
    
    // 读取API密钥
    if (offset + sizeof(uint32_t) > payload.size()) {
        return false;
    }
    uint32_t api_key_len;
    std::memcpy(&api_key_len, payload.data() + offset, sizeof(uint32_t));
    offset += sizeof(uint32_t);
    
    if (offset + api_key_len > payload.size()) {
        return false;
    }
    api_key_.assign(reinterpret_cast<const char*>(payload.data() + offset), api_key_len);
    offset += api_key_len;
    
    return true;
}

} // namespace protocol
} // namespace ft 