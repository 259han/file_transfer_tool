#include "server_core.h"
#include "server_config.h"
#include "../../common/utils/logging/logger.h"
#include <filesystem>

namespace fs = std::filesystem;

namespace ft {
namespace server {

// 静态成员初始化  
std::string ServerCore::storage_path_ = "./storage";

ServerCore::ServerCore() : running_(false) {
}

ServerCore::~ServerCore() {
    stop();
}

bool ServerCore::initialize(const ServerConfig& user_config, utils::LogLevel log_level) {
    // 注意：这里接受的config参数主要用于外部传入配置
    // 但我们使用单例的ServerConfig来存储配置
    ServerConfig& config = ServerConfig::instance();
    
    // 如果传入了配置，则更新单例配置
    config.set_listen_address(user_config.get_listen_address());
    config.set_listen_port(user_config.get_listen_port());
    config.set_storage_path(user_config.get_storage_path());
    config.set_log_level(user_config.get_log_level());
    config.set_log_file(user_config.get_log_file());
    config.set_max_connections(user_config.get_max_connections());
    config.set_thread_pool_size(user_config.get_thread_pool_size());
    config.set_encryption_enabled(user_config.is_encryption_enabled());
    config.set_users_file(user_config.get_users_file());
    config.set_tcp_optimization_enabled(user_config.is_tcp_optimization_enabled());
    config.set_tcp_send_buffer_size(user_config.get_tcp_send_buffer_size());
    config.set_tcp_recv_buffer_size(user_config.get_tcp_recv_buffer_size());
    config.set_zero_copy_enabled(user_config.is_zero_copy_enabled());
    
    // 初始化日志系统
    ft::utils::Logger::instance().init(
        log_level, 
        true, 
        config.get_log_file()
    );
    
    LOG_INFO("Initializing server core...");
    
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
    if (!utils::UserManager::instance().initialize(config.get_users_file())) {
        LOG_ERROR("Failed to initialize user manager with file: %s", config.get_users_file().c_str());
        return false;
    }
    
    // 创建线程池
    size_t thread_count = config.get_thread_pool_size();
    if (thread_count == 0) {
        thread_count = std::thread::hardware_concurrency();
    }
    thread_pool_ = std::make_unique<utils::ThreadPool>(thread_count);
    LOG_INFO("Thread pool initialized with %zu threads", thread_count);
    
    // 创建TCP监听器
    network::SocketOptions socket_options;
    
    // 应用TCP优化配置
    if (config.is_tcp_optimization_enabled()) {
        LOG_INFO("Applying TCP optimizations");
        socket_options.recv_buffer_size = config.get_tcp_recv_buffer_size();
        socket_options.send_buffer_size = config.get_tcp_send_buffer_size();
        socket_options.non_blocking = true;
        socket_options.reuse_address = true;
        socket_options.reuse_port = true;
        
        LOG_INFO("TCP buffer sizes: send=%d, recv=%d", 
                 socket_options.send_buffer_size, socket_options.recv_buffer_size);
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
    
    LOG_INFO("Server listening on %s:%d", 
             config.get_listen_address().c_str(), config.get_listen_port());
    LOG_INFO("Zero-copy transfer: %s", config.is_zero_copy_enabled() ? "enabled" : "disabled");
    
    return true;
}

bool ServerCore::start() {
    if (running_) {
        LOG_WARNING("Server is already running");
        return true;
    }
    
    LOG_INFO("Starting server...");
    running_ = true;
    
    // 启动接受连接线程
    accept_thread_ = std::thread(&ServerCore::run, this);
    
    LOG_INFO("Server started successfully");
    return true;
}

void ServerCore::wait() {
    if (accept_thread_.joinable()) {
        accept_thread_.join();
    }
}

bool ServerCore::is_running() const {
    return running_;
}

size_t ServerCore::get_session_count() const {
    std::lock_guard<std::mutex> lock(sessions_mutex_);
    return sessions_.size();
}

bool ServerCore::init(const std::string& config_file) {
    // 加载配置
    ServerConfig& config = ServerConfig::instance();
    if (!config_file.empty()) {
        if (!config.load_from_file(config_file)) {
            LOG_ERROR("Failed to load configuration from file: %s", config_file.c_str());
            return false;
        }
    }
    
    // 初始化日志系统
    ft::utils::Logger::instance().init(
        static_cast<ft::utils::LogLevel>(config.get_log_level()), 
        true, 
        config.get_log_file()
    );
    
    LOG_INFO("Initializing server core...");
    
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
    if (!utils::UserManager::instance().initialize(config.get_users_file())) {
        LOG_ERROR("Failed to initialize user manager with file: %s", config.get_users_file().c_str());
        return false;
    }
    
    // 创建线程池
    size_t thread_count = config.get_thread_pool_size();
    if (thread_count == 0) {
        thread_count = std::thread::hardware_concurrency();
    }
    thread_pool_ = std::make_unique<utils::ThreadPool>(thread_count);
    LOG_INFO("Thread pool initialized with %zu threads", thread_count);
    
    // 创建TCP监听器
    network::SocketOptions socket_options;
    
    // 应用TCP优化配置
    if (config.is_tcp_optimization_enabled()) {
        LOG_INFO("Applying TCP optimizations");
        socket_options.recv_buffer_size = config.get_tcp_recv_buffer_size();
        socket_options.send_buffer_size = config.get_tcp_send_buffer_size();
        socket_options.non_blocking = true;
        socket_options.reuse_address = true;
        socket_options.reuse_port = true;
        
        LOG_INFO("TCP buffer sizes: send=%d, recv=%d", 
                 socket_options.send_buffer_size, socket_options.recv_buffer_size);
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
    
    LOG_INFO("Server listening on %s:%d", 
             config.get_listen_address().c_str(), config.get_listen_port());
    LOG_INFO("Zero-copy transfer: %s", config.is_zero_copy_enabled() ? "enabled" : "disabled");
    
    running_ = true;
    return true;
}

void ServerCore::run() {
    LOG_INFO("Server core running...");
    
    while (running_) {
        // 接受新连接
        auto client_socket = listener_->accept();
        if (!client_socket) {
            if (!running_) {
                break;  // 服务器已停止
            }
            
            LOG_ERROR("Failed to accept client connection: %d", 
                     static_cast<int>(listener_->get_last_error()));
            continue;
        }
        
        // 创建新会话
        size_t session_id;
        {
            std::lock_guard<std::mutex> lock(sessions_mutex_);
            session_id = next_session_id_++;
            
            // 检查是否超过最大连接数
            if (sessions_.size() >= ServerConfig::instance().get_max_connections()) {
                LOG_WARNING("Maximum connections reached (%zu), rejecting new connection", 
                           ServerConfig::instance().get_max_connections());
                continue;
            }
            
            // 创建新的客户端会话
            auto session = std::make_shared<ClientSession>(std::move(client_socket));
            
            // 零拷贝配置在会话内部处理
            
            // 添加到会话列表
            sessions_[session_id] = session;
        }
        
        LOG_INFO("New client connected: session_id=%zu", session_id);
        
        // 在线程池中处理会话
        thread_pool_->enqueue([this, session_id]() {
            handle_client_session(session_id);
        });
    }
    
    LOG_INFO("Server core stopped");
}

void ServerCore::stop() {
    LOG_INFO("Stopping server core...");
    
    running_ = false;
    
    // 关闭监听器
    if (listener_) {
        listener_->close();
    }
    
    // 关闭所有会话
    {
        std::lock_guard<std::mutex> lock(sessions_mutex_);
        for (auto& pair : sessions_) {
            pair.second->stop();
        }
        sessions_.clear();
    }
    
    // 停止线程池
    if (thread_pool_) {
        thread_pool_->stop();
    }
    
    LOG_INFO("Server core cleanup completed");
}

void ServerCore::handle_client_session(size_t session_id) {
    std::shared_ptr<ClientSession> session;
    
    // 获取会话
    {
        std::lock_guard<std::mutex> lock(sessions_mutex_);
        auto it = sessions_.find(session_id);
        if (it == sessions_.end()) {
            LOG_ERROR("Session %zu not found", session_id);
            return;
        }
        session = it->second;
    }
    
    try {
        // 处理会话
        session->start();
    } catch (const std::exception& e) {
        LOG_ERROR("Exception in session %zu: %s", session_id, e.what());
    }
    
    // 会话结束，移除
    {
        std::lock_guard<std::mutex> lock(sessions_mutex_);
        auto it = sessions_.find(session_id);
        if (it != sessions_.end()) {
            LOG_INFO("Session %zu closed", session_id);
            sessions_.erase(it);
            
        }
    }
}

utils::UserManager* ServerCore::get_user_manager() {
    return &utils::UserManager::instance();
}

} // namespace server
} // namespace ft 