#pragma once

#include <string>
#include <memory>
#include "../../common/protocol/messages/authentication_message.h"
#include "../../common/network/socket/tcp_socket.h"

namespace ft {
namespace client {

/**
 * @brief 客户端认证结果结构体
 */
struct AuthenticationResult {
    bool success;                    // 是否认证成功
    std::string error_message;       // 错误信息
    std::string session_id;          // 认证会话ID
    std::string username;            // 认证用户名
    uint8_t permissions;             // 用户权限
    
    AuthenticationResult()
        : success(false),
          error_message(""),
          session_id(""),
          username(""),
          permissions(0) {
    }
};

/**
 * @brief 客户端认证处理器类
 */
class ClientAuthenticationHandler {
public:
    /**
     * @brief 构造函数
     */
    ClientAuthenticationHandler();
    
    /**
     * @brief 析构函数
     */
    ~ClientAuthenticationHandler();
    
    /**
     * @brief 用户名密码认证
     * @param socket 网络连接
     * @param username 用户名
     * @param password 密码
     * @return 认证结果
     */
    AuthenticationResult authenticate_user(network::TcpSocket& socket,
                                         const std::string& username,
                                         const std::string& password);
    
    /**
     * @brief API密钥认证
     * @param socket 网络连接
     * @param api_key API密钥
     * @return 认证结果
     */
    AuthenticationResult authenticate_api_key(network::TcpSocket& socket,
                                            const std::string& api_key);
    
    /**
     * @brief 检查是否已认证
     * @return 是否已认证
     */
    bool is_authenticated() const;
    
    /**
     * @brief 获取认证会话ID
     * @return 会话ID
     */
    const std::string& get_session_id() const;
    
    /**
     * @brief 获取认证用户名
     * @return 用户名
     */
    const std::string& get_username() const;
    
    /**
     * @brief 获取用户权限
     * @return 权限位掩码
     */
    uint8_t get_permissions() const;
    
    /**
     * @brief 检查是否有指定权限
     * @param permission 权限类型
     * @return 是否有权限
     */
    bool has_permission(uint8_t permission) const;
    
    /**
     * @brief 清除认证状态
     */
    void clear_authentication();

private:
    /**
     * @brief 发送认证请求
     * @param socket 网络连接
     * @param auth_msg 认证消息
     * @return 是否发送成功
     */
    bool send_auth_request(network::TcpSocket& socket, 
                          const protocol::AuthenticationMessage& auth_msg);
    
    /**
     * @brief 接收认证响应
     * @param socket 网络连接
     * @return 认证结果
     */
    AuthenticationResult receive_auth_response(network::TcpSocket& socket);

private:
    bool authenticated_;               // 是否已认证
    std::string session_id_;          // 认证会话ID
    std::string username_;            // 认证用户名
    uint8_t permissions_;             // 用户权限
};

} // namespace client
} // namespace ft 