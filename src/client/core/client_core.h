#pragma once

#include <string>
#include <vector>
#include <thread>
#include <atomic>
#include <memory>
#include <functional>
#include <future>
#include "../../common/network/socket/tcp_socket.h"
#include "../../common/utils/crypto/encryption.h"
#include "../../common/utils/logging/logger.h"
#include <filesystem>

namespace fs = std::filesystem;

namespace ft {

// 前向声明测试类
namespace test {
class TestableClientCore;
}

namespace client {

// 前向声明
class ClientAuthenticationHandler;
struct AuthenticationResult;

/**
 * @brief 传输请求结构体
 */
struct TransferRequest {
    std::string local_file;    // 本地文件路径
    std::string remote_file;   // 远程文件路径
    size_t chunk_size;         // 分块大小
    bool resume;               // 是否断点续传
    
    TransferRequest()
        : local_file(""), 
          remote_file(""),
          chunk_size(1024 * 1024),  // 默认1MB
          resume(false) {
    }
};

/**
 * @brief 传输结果结构体
 */
struct TransferResult {
    bool success;                  // 是否成功
    std::string error_message;     // 错误信息
    size_t total_bytes;            // 总字节数
    size_t transferred_bytes;      // 已传输字节数
    double elapsed_seconds;        // 耗时(秒)
    
    TransferResult()
        : success(false),
          error_message(""),
          total_bytes(0),
          transferred_bytes(0),
          elapsed_seconds(0.0) {
    }
};

/**
 * @brief 服务器信息结构体
 */
struct ServerInfo {
    std::string host;          // 主机名或IP地址
    uint16_t port;             // 端口号
    std::string username;      // 用户名
    std::string password;      // 密码
    
    ServerInfo()
        : host("localhost"),
          port(12345),
          username(""),
          password("") {
    }
};

/**
 * @brief 客户端核心类
 */
class ClientCore {
public:
    using ProgressCallback = std::function<void(size_t, size_t)>;
    
    // 为测试目的添加友元类声明
    friend class ft::test::TestableClientCore;
    
    /**
     * @brief 构造函数
     */
    ClientCore();
    
    /**
     * @brief 析构函数
     */
    ~ClientCore();
    
    /**
     * @brief 初始化客户端
     * @param log_level 日志级别
     * @return 是否初始化成功
     */
    bool initialize(utils::LogLevel log_level = utils::LogLevel::INFO);
    
    /**
     * @brief 加密控制
     * @return 是否启用加密
     */
    bool enable_encryption();
    
    /**
     * @brief 加密控制
     * @return 是否禁用加密
     */
    bool disable_encryption();
    
    /**
     * @brief 是否已启用加密
     * @return 是否已启用加密
     */
    bool is_encryption_enabled() const;
    
    /**
     * @brief 连接到服务器
     * @param server 服务器信息
     * @return 是否连接成功
     */
    bool connect(const ServerInfo& server);
    
    /**
     * @brief 断开与服务器的连接
     */
    void disconnect();
    
    /**
     * @brief 是否已连接
     * @return 是否已连接
     */
    bool is_connected() const;
    
    /**
     * @brief 上传文件
     * @param request 传输请求
     * @return 传输结果
     */
    TransferResult upload(const TransferRequest& request);
    
    /**
     * @brief 异步上传文件
     * @param request 传输请求
     * @return 传输结果的future对象
     */
    std::future<TransferResult> upload_async(const TransferRequest& request);
    
    /**
     * @brief 下载文件
     * @param request 传输请求
     * @return 传输结果
     */
    TransferResult download(const TransferRequest& request);
    
    /**
     * @brief 异步下载文件
     * @param request 传输请求
     * @return 传输结果的future对象
     */
    std::future<TransferResult> download_async(const TransferRequest& request);
    
    /**
     * @brief 设置进度回调函数
     * @param callback 回调函数
     */
    void set_progress_callback(ProgressCallback callback) {
        progress_callback_ = std::move(callback);
    }
    
    /**
     * @brief 获取底层套接字
     * @return 套接字指针
     */
    network::TcpSocket* get_socket() const {
        return socket_.get();
    }
    
    /**
     * @brief 发送心跳包
     * @return 是否成功
     */
    bool send_heartbeat();
    
    /**
     * @brief 认证用户
     * @param username 用户名
     * @param password 密码
     * @return 认证结果
     */
    AuthenticationResult authenticate(const std::string& username, const std::string& password);
    
    /**
     * @brief 使用API密钥认证
     * @param api_key API密钥
     * @return 认证结果
     */
    AuthenticationResult authenticate_with_api_key(const std::string& api_key);
    
    /**
     * @brief 检查是否已认证
     * @return 是否已认证
     */
    bool is_authenticated() const;
    
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
    
    /**
     * @brief 连接到服务器（便利方法）
     * @param host 主机名或IP地址
     * @param port 端口号
     * @return 是否连接成功
     */
    bool connect(const std::string& host, uint16_t port) {
        ServerInfo server;
        server.host = host;
        server.port = port;
        return connect(server);
    }
    
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
    
private:
    /**
     * @brief 启动心跳线程
     */
    void start_heartbeat_thread();
    
    /**
     * @brief 停止心跳线程
     */
    void stop_heartbeat_thread();
    
    /**
     * @brief 心跳检测循环
     */
    void heartbeat_loop();
    
    /**
     * @brief 执行密钥交换
     * @return 是否成功
     */
    bool perform_key_exchange();
    
    ServerInfo server_info_;
    std::unique_ptr<network::TcpSocket> socket_;
    ProgressCallback progress_callback_;
    bool is_connected_;
    std::thread heartbeat_thread_;      // 心跳线程
    std::atomic<bool> stop_heartbeat_;  // 停止心跳线程标志
    
    // 加密相关
    bool encryption_enabled_;
    std::vector<uint8_t> encryption_key_;
    std::vector<uint8_t> encryption_iv_;
    
    // 密钥交换相关
    std::vector<uint8_t> dh_private_key_;
    bool key_exchange_completed_;
    
    // 认证相关
    bool authenticated_;
    std::string authenticated_username_;
    uint8_t user_permissions_;
    std::unique_ptr<ClientAuthenticationHandler> auth_handler_;
};

} // namespace client
} // namespace ft 