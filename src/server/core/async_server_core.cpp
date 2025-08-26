#include "async_server_core.h"
#include "../../common/utils/logging/logger.h"
#include <filesystem>
#include <chrono>

namespace fs = std::filesystem;

namespace ft {
namespace server {

// 静态成员初始化
std::unique_ptr<network::AsyncIOManager> AsyncServerCore::async_io_manager_;
std::unique_ptr<network::TcpSocket> AsyncServerCore::listener_;
std::unordered_map<size_t, std::unique_ptr<ClientSession>> AsyncServerCore::sessions_;
std::unordered_map<int, size_t> AsyncServerCore::fd_to_session_;
std::mutex AsyncServerCore::sessions_mutex_;
size_t AsyncServerCore::next_session_id_ = 1;
std::atomic<bool> AsyncServerCore::running_(false);
std::string AsyncServerCore::storage_path_ = "./storage";
std::atomic<size_t> AsyncServerCore::total_connections_(0);
std::chrono::steady_clock::time_point AsyncServerCore::start_time_;

bool AsyncServerCore::init(const std::string& config_file) {
    // 加载配置
    ServerConfig& config = ServerConfig::instance();
    if (!config_file.empty()) {
        if (!config.load_from_file(config_file)) {
            LOG_ERROR("Failed to load configuration from file: %s", config_file.c_str());
            return false;
        }
    }
    
    // 初始化日志系统
    ft::utils::Logger::instance().set_level(static_cast<ft::utils::LogLevel>(config.get_log_level()));
    if (!config.get_log_file().empty()) {
        ft::utils::Logger::instance().set_file_output(config.get_log_file(), 10 * 1024 * 1024);
    }
    
    LOG_INFO("Initializing async server core...");
    
    // 创建存储目录
    storage_path_ = config.get_storage_path();
    if (!fs::exists(storage_path_)) {
        LOG_INFO("Creating storage directory: %s", storage_path_.c_str());
        try {
            fs::create_directories(storage_path_);
        } catch (const std::exception& e) {
            LOG_ERROR("Failed to create storage directory: %s", e.what());
            return false;
        }
    }
    
    // 初始化用户管理器
    auto& user_manager = ft::utils::UserManager::instance();
    if (!user_manager.initialize(config.get_users_file()) || !user_manager.load_users()) {
        LOG_ERROR("Failed to load users from: %s", config.get_users_file().c_str());
        return false;
    }
    
    // 创建异步I/O管理器
    async_io_manager_ = std::make_unique<network::AsyncIOManager>();
    
    size_t worker_threads = config.get_thread_pool_size();
    if (worker_threads == 0) {
        worker_threads = std::thread::hardware_concurrency();
        if (worker_threads == 0) worker_threads = 4;
    }
    
    if (!async_io_manager_->initialize(worker_threads)) {
        LOG_ERROR("Failed to initialize AsyncIOManager");
        return false;
    }
    
    LOG_INFO("AsyncIOManager initialized with %zu worker threads", worker_threads);
    
    // 创建TCP监听器
    network::SocketOptions socket_options;
    
    // 应用TCP优化配置
    if (config.is_tcp_optimization_enabled()) {
        LOG_INFO("Applying TCP optimizations");
        socket_options.recv_buffer_size = config.get_tcp_recv_buffer_size();
        socket_options.send_buffer_size = config.get_tcp_send_buffer_size();
        socket_options.non_blocking = true;  // 异步模式必须非阻塞
        socket_options.reuse_address = true;
        socket_options.reuse_port = true;
        
        LOG_INFO("TCP buffer sizes: send=%d, recv=%d", 
                 socket_options.send_buffer_size, socket_options.recv_buffer_size);
    } else {
        // 即使不启用TCP优化，异步模式也需要非阻塞
        socket_options.non_blocking = true;
    }
    
    listener_ = std::make_unique<network::TcpSocket>(socket_options);
    
    // 绑定监听地址和端口
    network::SocketError err = listener_->bind(config.get_listen_address(), config.get_listen_port());
    if (err != network::SocketError::SUCCESS) {
        LOG_ERROR("Failed to bind to %s:%d", 
                 config.get_listen_address().c_str(), config.get_listen_port());
        return false;
    }
    
    // 开始监听
    err = listener_->listen();
    if (err != network::SocketError::SUCCESS) {
        LOG_ERROR("Failed to listen on %s:%d", 
                 config.get_listen_address().c_str(), config.get_listen_port());
        return false;
    }
    
    LOG_INFO("Async server listening on %s:%d", 
             config.get_listen_address().c_str(), config.get_listen_port());
    LOG_INFO("Zero-copy transfer: %s", config.is_zero_copy_enabled() ? "enabled" : "disabled");
    
    return true;
}

void AsyncServerCore::run() {
    LOG_INFO("Starting async server core...");
    start_time_ = std::chrono::steady_clock::now();
    
    // 启动异步I/O管理器
    if (!async_io_manager_->start()) {
        LOG_ERROR("Failed to start AsyncIOManager");
        return;
    }
    
    // 设置监听socket的异步接受回调
    int listen_fd = listener_->get_fd();
    async_io_manager_->async_accept(listen_fd, [](int fd) {
        handle_new_connection(fd);
    });
    
    running_ = true;
    LOG_INFO("Async server core running...");
    
    // 主线程进入事件循环（已由AsyncIOManager管理）
    while (running_) {
        std::this_thread::sleep_for(std::chrono::milliseconds(1000));
        
        // 定期打印统计信息
        if (LOG_LEVEL <= ft::utils::LogLevel::INFO) {
            auto stats = get_statistics();
            LOG_INFO("Server stats: connections=%zu, events/sec=%.1f, pending_tasks=%zu",
                    stats.active_connections, static_cast<double>(stats.events_per_second), stats.pending_tasks);
        }
    }
    
    LOG_INFO("Async server core stopped");
}

void AsyncServerCore::stop() {
    LOG_INFO("Stopping async server core...");
    
    running_ = false;
    
    // 关闭监听器
    if (listener_) {
        listener_->close();
    }
    
    // 关闭所有会话
    {
        std::lock_guard<std::mutex> lock(sessions_mutex_);
        for (auto& pair : sessions_) {
            pair.second->stop();  // 使用ClientSession的stop方法
        }
        sessions_.clear();
        fd_to_session_.clear();
    }
    
    // 停止异步I/O管理器
    if (async_io_manager_) {
        async_io_manager_->stop();
    }
    
    LOG_INFO("Async server core cleanup completed");
}

void AsyncServerCore::handle_new_connection(int /* listen_fd */) {
    // 接受新连接
    auto client_socket = listener_->accept();
    if (!client_socket) {
        if (running_) {
            LOG_ERROR("Failed to accept client connection: %d", 
                     static_cast<int>(listener_->get_last_error()));
        }
        return;
    }
    
    // 检查连接数限制
    {
        std::lock_guard<std::mutex> lock(sessions_mutex_);
        if (sessions_.size() >= ServerConfig::instance().get_max_connections()) {
            LOG_WARNING("Maximum connections reached (%zu), rejecting new connection", 
                       ServerConfig::instance().get_max_connections());
            return;
        }
    }
    
    // 创建新会话
    size_t session_id = next_session_id_++;
    int client_fd = client_socket->get_fd();
    
    // 设置客户端socket为非阻塞
    client_socket->set_non_blocking(true);
    
    // 保存客户端信息（在ClientSession创建前）
    std::string remote_ip = client_socket->get_remote_ip();
    uint16_t remote_port = client_socket->get_remote_port();
    
    auto session = std::make_unique<ClientSession>(std::move(client_socket));
    
    // 注意：当前ClientSession不支持零拷贝配置
    // 零拷贝功能需要在会话内部处理
    
    {
        std::lock_guard<std::mutex> lock(sessions_mutex_);
        sessions_[session_id] = std::move(session);
        fd_to_session_[client_fd] = session_id;
    }
    
    total_connections_++;
    
    LOG_INFO("New client connected: session_id=%zu, fd=%d, remote=%s:%d", 
            session_id, client_fd, remote_ip.c_str(), remote_port);
    
    // 注册客户端socket的异步读取事件
    async_io_manager_->async_read(client_fd, [session_id](int fd, bool available) {
        if (available) {
            handle_client_read_ready(fd, session_id);
        } else {
            handle_client_error(fd, session_id);
        }
    });
}

void AsyncServerCore::handle_client_read_ready(int /* client_fd */, size_t session_id) {
    // 将业务逻辑处理提交到工作线程池
    async_io_manager_->submit_task([session_id]() {
        process_client_session(session_id);
    });
}

void AsyncServerCore::handle_client_write_ready(int client_fd, size_t session_id) {
    // 当前实现暂时不需要特殊的写就绪处理
    // 可以在此处理写缓冲区满的情况
    LOG_DEBUG("Client fd %d (session %zu) write ready", client_fd, session_id);
}

void AsyncServerCore::handle_client_error(int client_fd, size_t session_id) {
    LOG_INFO("Client fd %d (session %zu) error or disconnect", client_fd, session_id);
    cleanup_session(session_id);
}

void AsyncServerCore::process_client_session(size_t session_id) {
    ClientSession* session = nullptr;
    
    // 获取会话
    {
        std::lock_guard<std::mutex> lock(sessions_mutex_);
        auto it = sessions_.find(session_id);
        if (it == sessions_.end()) {
            LOG_ERROR("Session %zu not found", session_id);
            return;
        }
        session = it->second.get();
    }
    
    try {
        // 处理会话 - 保持现有业务逻辑不变
        session->process();
    } catch (const std::exception& e) {
        LOG_ERROR("Exception in session %zu: %s", session_id, e.what());
    }
    
    // 会话处理完毕，清理
    cleanup_session(session_id);
}

void AsyncServerCore::cleanup_session(size_t session_id) {
    std::lock_guard<std::mutex> lock(sessions_mutex_);
    auto it = sessions_.find(session_id);
    if (it != sessions_.end()) {
        int client_fd = it->second->get_socket().get_fd();
        std::string client_addr = it->second->get_client_address();
        
        LOG_INFO("Session %zu closed: fd=%d, remote=%s", 
                session_id, client_fd, client_addr.c_str());
        
        // 从fd映射中移除
        fd_to_session_.erase(client_fd);
        
        // 移除会话
        sessions_.erase(it);
    }
}

const std::string& AsyncServerCore::get_storage_path() {
    return storage_path_;
}

ft::utils::UserManager* AsyncServerCore::get_user_manager() {
    return &ft::utils::UserManager::instance();
}

AsyncServerCore::Statistics AsyncServerCore::get_statistics() {
    Statistics stats = {};
    
    if (async_io_manager_) {
        auto async_stats = async_io_manager_->get_statistics();
        stats.active_connections = async_stats.active_connections;
        stats.events_per_second = static_cast<size_t>(async_stats.events_per_second);
        stats.pending_tasks = async_stats.pending_tasks;
    }
    
    stats.total_connections = total_connections_;
    stats.average_response_time = 0.0;  // TODO: 实现响应时间统计
    
    return stats;
}

} // namespace server
} // namespace ft
