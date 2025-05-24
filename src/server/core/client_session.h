#pragma once

#include <string>
#include <memory>
#include <thread>
#include <vector>
#include <atomic>
#include <mutex>
#include "../../common/network/socket/tcp_socket.h"
#include "../../common/utils/logging/logger.h"

namespace ft {
namespace server {

// 前向声明
class UploadHandler;
class DownloadHandler;
class KeyExchangeHandler;
class AuthenticationHandler;

/**
 * @brief 客户端会话类
 */
class ClientSession {
public:
    /**
     * @brief 构造函数
     * @param socket 客户端socket
     */
    explicit ClientSession(std::unique_ptr<network::TcpSocket> socket);
    
    /**
     * @brief 析构函数
     */
    ~ClientSession();
    
    /**
     * @brief 启动会话处理
     */
    void start();
    
    /**
     * @brief 停止会话处理
     */
    void stop();
    
    /**
     * @brief 获取客户端地址
     * @return 客户端地址
     */
    std::string get_client_address() const;
    
    /**
     * @brief 获取会话ID
     * @return 会话ID
     */
    size_t get_session_id() const;
    
    /**
     * @brief 检查会话是否已连接
     * @return 是否已连接
     */
    bool is_connected() const;
    
    /**
     * @brief 获取socket引用
     * @return socket引用
     */
    network::TcpSocket& get_socket();
    
    /**
     * @brief 检查是否启用加密
     * @return 是否启用加密
     */
    bool is_encryption_enabled() const;
    
    /**
     * @brief 检查密钥交换是否完成
     * @return 是否完成
     */
    bool is_key_exchange_completed() const;
    
    /**
     * @brief 加密数据
     * @param data 待加密数据
     * @return 加密后的数据
     */
    std::vector<uint8_t> encrypt_data(const std::vector<uint8_t>& data);
    
    /**
     * @brief 解密数据
     * @param data 待解密数据
     * @return 解密后的数据
     */
    std::vector<uint8_t> decrypt_data(const std::vector<uint8_t>& data);
    
    /**
     * @brief 设置加密参数
     * @param encryption_key 加密密钥
     * @param encryption_iv 加密IV
     * @param dh_private_key DH私钥
     */
    void set_encryption_params(const std::vector<uint8_t>& encryption_key,
                              const std::vector<uint8_t>& encryption_iv,
                              const std::vector<uint8_t>& dh_private_key);
    
    /**
     * @brief 启用加密
     */
    void enable_encryption();
    
    /**
     * @brief 检查是否已认证
     * @return 是否已认证
     */
    bool is_authenticated() const;
    
    /**
     * @brief 设置认证状态
     * @param session_id 认证会话ID
     * @param username 用户名
     * @param permissions 用户权限
     */
    void set_authenticated(const std::string& session_id, const std::string& username, uint8_t permissions);
    
    /**
     * @brief 清除认证状态
     */
    void clear_authentication();
    
    /**
     * @brief 获取认证会话ID
     * @return 会话ID
     */
    const std::string& get_auth_session_id() const;
    
    /**
     * @brief 获取认证用户名
     * @return 用户名
     */
    const std::string& get_authenticated_username() const;
    
    /**
     * @brief 获取用户权限
     * @return 权限位掩码
     */
    uint8_t get_user_permissions() const;
    
    /**
     * @brief 检查是否有指定权限
     * @param permission 权限类型
     * @return 是否有权限
     */
    bool has_permission(uint8_t permission) const;

private:
    /**
     * @brief 会话处理线程
     */
    void process();
    
    /**
     * @brief 处理心跳请求并发送响应
     * @param buffer 消息缓冲区
     * @return 是否处理成功
     */
    bool handle_heartbeat_response(const std::vector<uint8_t>& buffer);
    
    /**
     * @brief 处理认证请求
     * @param buffer 消息缓冲区
     * @return 是否处理成功
     */
    bool handle_authentication_request(const std::vector<uint8_t>& buffer);

private:
    static std::atomic<size_t> next_session_id_;
    
    size_t session_id_;
    std::unique_ptr<network::TcpSocket> socket_;
    std::thread thread_;
    std::atomic<bool> running_;
    
    // 加密相关
    bool encryption_enabled_;
    std::vector<uint8_t> encryption_key_;
    std::vector<uint8_t> encryption_iv_;
    std::vector<uint8_t> dh_private_key_;
    bool key_exchange_completed_;
    
    // 认证相关
    bool authenticated_;
    std::string auth_session_id_;
    std::string authenticated_username_;
    uint8_t user_permissions_;
    
    // 协议处理器
    std::unique_ptr<UploadHandler> upload_handler_;
    std::unique_ptr<DownloadHandler> download_handler_;
    std::unique_ptr<KeyExchangeHandler> key_exchange_handler_;
    std::unique_ptr<AuthenticationHandler> authentication_handler_;
};

} // namespace server
} // namespace ft 