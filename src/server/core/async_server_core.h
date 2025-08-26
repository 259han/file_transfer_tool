#pragma once

#include "server_config.h"
#include "../../common/network/async/event_loop.h"
#include "../../common/network/socket/tcp_socket.h"
#include "client_session.h"
#include "../../common/utils/auth/user_manager.h"
#include <memory>
#include <unordered_map>
#include <atomic>
#include <mutex>
#include <string>

namespace ft {
namespace server {

/**
 * @brief 异步服务器核心 - Reactor模式实现
 * 
 * 采用单线程Reactor模式：
 * - 主线程负责I/O事件检测（accept、read ready、write ready）
 * - 工作线程池负责业务逻辑处理
 * - 保持现有ClientSession业务逻辑不变
 */
class AsyncServerCore {
public:
    AsyncServerCore() = default;
    ~AsyncServerCore() = default;
    
    // 禁用拷贝
    AsyncServerCore(const AsyncServerCore&) = delete;
    AsyncServerCore& operator=(const AsyncServerCore&) = delete;
    
    /**
     * @brief 初始化异步服务器
     * @param config_file 配置文件路径
     * @return 是否成功初始化
     */
    static bool init(const std::string& config_file = "");
    
    /**
     * @brief 运行异步服务器（阻塞）
     */
    static void run();
    
    /**
     * @brief 停止异步服务器
     */
    static void stop();
    
    /**
     * @brief 获取存储路径
     */
    static const std::string& get_storage_path();
    
    /**
     * @brief 获取用户管理器
     */
    static ft::utils::UserManager* get_user_manager();
    
    /**
     * @brief 获取服务器统计信息
     */
    struct Statistics {
        size_t active_connections;
        size_t total_connections;
        size_t events_per_second;
        size_t pending_tasks;
        double average_response_time;
    };
    
    static Statistics get_statistics();

private:
    // 连接接受处理
    static void handle_new_connection(int listen_fd);
    
    // 客户端数据读取准备就绪
    static void handle_client_read_ready(int client_fd, size_t session_id);
    
    // 客户端数据写入准备就绪  
    static void handle_client_write_ready(int client_fd, size_t session_id);
    
    // 客户端连接错误处理
    static void handle_client_error(int client_fd, size_t session_id);
    
    // 在工作线程中处理客户端会话
    static void process_client_session(size_t session_id);
    
    // 清理已关闭的会话
    static void cleanup_session(size_t session_id);

private:
    // 基础设施
    static std::unique_ptr<network::AsyncIOManager> async_io_manager_;
    static std::unique_ptr<network::TcpSocket> listener_;
    
    // 会话管理
    static std::unordered_map<size_t, std::unique_ptr<ClientSession>> sessions_;
    static std::unordered_map<int, size_t> fd_to_session_;  // fd -> session_id映射
    static std::mutex sessions_mutex_;
    static size_t next_session_id_;
    
    // 运行状态
    static std::atomic<bool> running_;
    static std::string storage_path_;
    
    // 统计信息
    static std::atomic<size_t> total_connections_;
    static std::chrono::steady_clock::time_point start_time_;
};

} // namespace server
} // namespace ft
