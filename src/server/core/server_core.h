#pragma once

#include <string>
#include <memory>
#include <thread>
#include <vector>
#include <atomic>
#include <mutex>
#include <condition_variable>
#include <unordered_map>
#include "../../common/network/socket/tcp_socket.h"
#include "../../common/utils/logging/logger.h"

namespace ft {
namespace server {

/**
 * @brief 服务器配置结构体
 */
struct ServerConfig {
    std::string bind_address;       // 监听地址
    uint16_t port;                  // 监听端口
    std::string storage_path;       // 存储路径
    size_t max_connections;         // 最大连接数
    size_t thread_pool_size;        // 线程池大小
    
    ServerConfig()
        : bind_address("0.0.0.0"),
          port(12345),
          storage_path("./storage"),
          max_connections(100),
          thread_pool_size(4) {
    }
};

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
    
private:
    /**
     * @brief 会话处理线程
     */
    void process();
    
    /**
     * @brief 处理上传请求
     * @param buffer 消息缓冲区
     * @return 是否处理成功
     */
    bool handle_upload(const std::vector<uint8_t>& buffer);
    
    /**
     * @brief 处理下载请求
     * @param buffer 消息缓冲区
     * @return 是否处理成功
     */
    bool handle_download(const std::vector<uint8_t>& buffer);
    
private:
    static std::atomic<size_t> next_session_id_;
    
    size_t session_id_;
    std::unique_ptr<network::TcpSocket> socket_;
    std::thread thread_;
    std::atomic<bool> running_;
};

/**
 * @brief 服务器核心类
 */
class ServerCore {
public:
    /**
     * @brief 构造函数
     */
    ServerCore();
    
    /**
     * @brief 析构函数
     */
    ~ServerCore();
    
    /**
     * @brief 初始化服务器
     * @param config 服务器配置
     * @param log_level 日志级别
     * @return 是否初始化成功
     */
    bool initialize(const ServerConfig& config, utils::LogLevel log_level = utils::LogLevel::INFO);
    
    /**
     * @brief 启动服务器
     * @return 是否启动成功
     */
    bool start();
    
    /**
     * @brief 停止服务器
     */
    void stop();
    
    /**
     * @brief 是否正在运行
     * @return 是否正在运行
     */
    bool is_running() const;
    
    /**
     * @brief 等待服务器停止
     */
    void wait();
    
    /**
     * @brief 获取服务器配置
     * @return 服务器配置
     */
    const ServerConfig& get_config() const {
        return config_;
    }
    
    /**
     * @brief 获取当前会话数
     * @return 当前会话数
     */
    size_t get_session_count() const {
        std::lock_guard<std::mutex> lock(sessions_mutex_);
        return sessions_.size();
    }
    
    /**
     * @brief 获取存储路径
     * @return 存储路径
     */
    static const std::string& get_storage_path() {
        return storage_path_;
    }
    
private:
    /**
     * @brief 接受连接线程
     */
    void accept_thread();
    
    /**
     * @brief 管理会话线程
     */
    void session_manager_thread();
    
private:
    ServerConfig config_;
    std::unique_ptr<network::TcpSocket> listen_socket_;
    std::thread accept_thread_;
    std::thread session_manager_thread_;
    std::atomic<bool> running_;
    
    std::vector<std::shared_ptr<ClientSession>> sessions_;
    mutable std::mutex sessions_mutex_;
    std::condition_variable stop_cv_;
    std::mutex stop_mutex_;
    
    // 静态存储路径
    static std::string storage_path_;
};

} // namespace server
} // namespace ft 