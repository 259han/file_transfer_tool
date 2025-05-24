#pragma once

#include "../protocol.h"
#include <string>
#include <vector>
#include <cstdint>

namespace ft {
namespace protocol {

/**
 * @brief 认证类型枚举
 */
enum class AuthenticationType : uint8_t {
    USERNAME_PASSWORD = 1,  // 用户名密码认证
    API_KEY = 2,           // API密钥认证
    TOKEN = 3              // 令牌认证
};

/**
 * @brief 认证阶段枚举
 */
enum class AuthenticationPhase : uint8_t {
    AUTH_REQUEST = 1,      // 客户端认证请求
    AUTH_RESPONSE = 2,     // 服务器认证响应
    AUTH_CHALLENGE = 3     // 服务器质询（用于高级认证）
};

/**
 * @brief 认证结果枚举
 */
enum class AuthenticationResult : uint8_t {
    SUCCESS = 0,           // 认证成功
    INVALID_CREDENTIALS = 1, // 凭据无效
    USER_NOT_FOUND = 2,    // 用户不存在
    ACCOUNT_LOCKED = 3,    // 账户被锁定
    SERVER_ERROR = 4,      // 服务器错误
    UNSUPPORTED_TYPE = 5   // 不支持的认证类型
};

/**
 * @brief 用户权限枚举
 */
enum class UserPermission : uint8_t {
    READ = 0x01,           // 读权限（下载）
    WRITE = 0x02,          // 写权限（上传）
    DELETE = 0x04,         // 删除权限
    ADMIN = 0x08           // 管理权限
};

/**
 * @brief 认证消息类
 */
class AuthenticationMessage : public Message {
public:
    /**
     * @brief 构造函数
     * @param phase 认证阶段
     */
    explicit AuthenticationMessage(AuthenticationPhase phase = AuthenticationPhase::AUTH_REQUEST);
    
    /**
     * @brief 从通用消息构造
     * @param msg 通用消息对象
     */
    explicit AuthenticationMessage(const Message& msg);
    
    /**
     * @brief 获取认证阶段
     * @return 认证阶段
     */
    AuthenticationPhase get_auth_phase() const { return auth_phase_; }
    
    /**
     * @brief 设置认证阶段
     * @param phase 认证阶段
     */
    void set_auth_phase(AuthenticationPhase phase) { auth_phase_ = phase; }
    
    /**
     * @brief 获取认证类型
     * @return 认证类型
     */
    AuthenticationType get_auth_type() const { return auth_type_; }
    
    /**
     * @brief 设置认证类型
     * @param type 认证类型
     */
    void set_auth_type(AuthenticationType type) { auth_type_ = type; }
    
    /**
     * @brief 获取认证结果
     * @return 认证结果
     */
    AuthenticationResult get_auth_result() const { return auth_result_; }
    
    /**
     * @brief 设置认证结果
     * @param result 认证结果
     */
    void set_auth_result(AuthenticationResult result) { auth_result_ = result; }
    
    /**
     * @brief 获取用户名
     * @return 用户名
     */
    const std::string& get_username() const { return username_; }
    
    /**
     * @brief 设置用户名
     * @param username 用户名
     */
    void set_username(const std::string& username) { username_ = username; }
    
    /**
     * @brief 获取密码哈希
     * @return 密码哈希
     */
    const std::string& get_password_hash() const { return password_hash_; }
    
    /**
     * @brief 设置密码哈希
     * @param password_hash 密码哈希
     */
    void set_password_hash(const std::string& password_hash) { password_hash_ = password_hash; }
    
    /**
     * @brief 获取API密钥
     * @return API密钥
     */
    const std::string& get_api_key() const { return api_key_; }
    
    /**
     * @brief 设置API密钥
     * @param api_key API密钥
     */
    void set_api_key(const std::string& api_key) { api_key_ = api_key; }
    
    /**
     * @brief 获取用户权限
     * @return 用户权限位掩码
     */
    uint8_t get_permissions() const { return permissions_; }
    
    /**
     * @brief 设置用户权限
     * @param permissions 权限位掩码
     */
    void set_permissions(uint8_t permissions) { permissions_ = permissions; }
    
    /**
     * @brief 检查是否有指定权限
     * @param permission 权限类型
     * @return 是否有权限
     */
    bool has_permission(UserPermission permission) const;
    
    /**
     * @brief 添加权限
     * @param permission 权限类型
     */
    void add_permission(UserPermission permission);
    
    /**
     * @brief 移除权限
     * @param permission 权限类型
     */
    void remove_permission(UserPermission permission);
    
    /**
     * @brief 设置用户名密码认证信息
     * @param username 用户名
     * @param password_hash 密码哈希
     */
    void set_username_password_auth(const std::string& username, const std::string& password_hash);
    
    /**
     * @brief 设置API密钥认证信息
     * @param api_key API密钥
     */
    void set_api_key_auth(const std::string& api_key);
    
    /**
     * @brief 编码消息
     * @param buffer 输出缓冲区
     * @return 是否成功
     */
    bool encode(std::vector<uint8_t>& buffer) override;
    
    /**
     * @brief 解码消息
     * @param buffer 输入缓冲区
     * @return 是否成功
     */
    bool decode(const std::vector<uint8_t>& buffer) override;

private:
    AuthenticationPhase auth_phase_;
    AuthenticationType auth_type_;
    AuthenticationResult auth_result_;
    std::string username_;
    std::string password_hash_;
    std::string api_key_;
    uint8_t permissions_;
};

} // namespace protocol
} // namespace ft 