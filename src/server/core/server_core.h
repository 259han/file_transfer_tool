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
#include "../../common/utils/threading/thread_pool.h"
#include "../../common/utils/auth/user_manager.h"
#include "server_config.h"
#include "client_session.h"

namespace ft {
namespace server {

// ServerConfig 类已在 server_config.h 中定义

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
     * @brief 初始化服务器（兼容性方法）
     * @param config_file 配置文件路径
     * @return 是否初始化成功
     */
    bool init(const std::string& config_file);
    
    /**
     * @brief 运行服务器
     */
    void run();
    
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
        return ServerConfig::instance();
    }
    
    /**
     * @brief 获取当前会话数
     * @return 当前会话数
     */
    size_t get_session_count() const;
    
    /**
     * @brief 获取存储路径
     * @return 存储路径
     */
    static const std::string& get_storage_path() {
        return storage_path_;
    }
    
    /**
     * @brief 获取用户管理器
     * @return 用户管理器指针
     */
    utils::UserManager* get_user_manager();
    
private:
    /**
     * @brief 接受连接线程
     */
    void accept_thread();
    
    /**
     * @brief 管理会话线程
     */
    void session_manager_thread();
    
    /**
     * @brief 处理客户端会话
     * @param session_id 会话ID
     */
    void handle_client_session(size_t session_id);
    
private:
    std::unique_ptr<network::TcpSocket> listen_socket_;
    std::unique_ptr<network::TcpSocket> listener_;  // 兼容性成员
    std::thread accept_thread_;
    std::thread session_manager_thread_;
    std::atomic<bool> running_;
    
    std::condition_variable stop_cv_;
    std::mutex stop_mutex_;
    
    // 会话管理
    std::unordered_map<size_t, std::shared_ptr<ClientSession>> sessions_;
    mutable std::mutex sessions_mutex_;  // mutable 以支持 const 成员函数中的加锁
    std::atomic<size_t> next_session_id_{1};
    
    // 线程池
    std::unique_ptr<utils::ThreadPool> thread_pool_;
    
    // 静态存储路径
    static std::string storage_path_;
};

} // namespace server
} // namespace ft 