#pragma once

#include "../../common/protocol/messages/authentication_message.h"
#include "../../common/utils/auth/user_manager.h"
#include "../../common/network/socket/tcp_socket.h"
#include <string>
#include <memory>

namespace ft {
namespace server {

/**
 * @brief 认证处理器类
 */
class AuthenticationHandler {
public:
    /**
     * @brief 构造函数
     */
    AuthenticationHandler();
    
    /**
     * @brief 析构函数
     */
    ~AuthenticationHandler();
    
    /**
     * @brief 处理认证请求
     * @param socket 客户端连接
     * @param auth_msg 认证消息
     * @return 是否处理成功
     */
    bool handle_authentication_request(std::shared_ptr<network::TcpSocket> socket, 
                                     const protocol::AuthenticationMessage& auth_msg);
    
    /**
     * @brief 验证会话是否已认证
     * @param session_id 会话ID
     * @return 是否已认证
     */
    bool is_session_authenticated(const std::string& session_id) const;
    
    /**
     * @brief 获取会话用户名
     * @param session_id 会话ID
     * @return 用户名，如果会话不存在返回空字符串
     */
    std::string get_session_username(const std::string& session_id) const;
    
    /**
     * @brief 获取会话权限
     * @param session_id 会话ID
     * @return 权限位掩码
     */
    uint8_t get_session_permissions(const std::string& session_id) const;
    
    /**
     * @brief 检查会话权限
     * @param session_id 会话ID
     * @param permission 权限类型
     * @return 是否有权限
     */
    bool has_session_permission(const std::string& session_id, protocol::UserPermission permission) const;
    
    /**
     * @brief 注销会话
     * @param session_id 会话ID
     */
    void logout_session(const std::string& session_id);
    
    /**
     * @brief 清理过期会话
     */
    void cleanup_expired_sessions();

private:
    /**
     * @brief 会话信息结构体
     */
    struct SessionInfo {
        std::string username;
        std::string auth_type; // "user" 或 "apikey"
        uint8_t permissions;
        std::chrono::system_clock::time_point created_at;
        std::chrono::system_clock::time_point last_activity;
        
        SessionInfo() : permissions(0) {}
    };
    
    /**
     * @brief 处理用户名密码认证
     * @param socket 客户端连接
     * @param auth_msg 认证消息
     * @return 是否处理成功
     */
    bool handle_username_password_auth(std::shared_ptr<network::TcpSocket> socket,
                                     const protocol::AuthenticationMessage& auth_msg);
    
    /**
     * @brief 处理API密钥认证
     * @param socket 客户端连接
     * @param auth_msg 认证消息
     * @return 是否处理成功
     */
    bool handle_api_key_auth(std::shared_ptr<network::TcpSocket> socket,
                           const protocol::AuthenticationMessage& auth_msg);
    
    /**
     * @brief 发送认证响应
     * @param socket 客户端连接
     * @param result 认证结果
     * @param session_id 会话ID（可选）
     * @param permissions 用户权限
     * @return 是否发送成功
     */
    bool send_auth_response(std::shared_ptr<network::TcpSocket> socket,
                          protocol::AuthenticationResult result,
                          const std::string& session_id = "",
                          uint8_t permissions = 0);
    
    /**
     * @brief 生成会话ID
     * @return 唯一的会话ID
     */
    std::string generate_session_id();
    
    /**
     * @brief 创建会话
     * @param username 用户名
     * @param auth_type 认证类型
     * @param permissions 用户权限
     * @return 会话ID
     */
    std::string create_session(const std::string& username, const std::string& auth_type, uint8_t permissions);

private:
    utils::UserManager& user_manager_;
    std::map<std::string, SessionInfo> sessions_; // session_id -> SessionInfo
    mutable std::mutex sessions_mutex_;
    
    // 会话配置
    static const int SESSION_TIMEOUT_MINUTES = 60; // 会话超时时间
};

} // namespace server
} // namespace ft 