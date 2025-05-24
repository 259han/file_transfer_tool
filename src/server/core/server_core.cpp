#include "server_core.h"
#include "client_session.h"
#include "../session/session_manager.h"
#include "../../common/utils/logging/logger.h"
#include "../../common/utils/auth/user_manager.h"
#include <filesystem>
#include <iostream>
#include <thread>
#include <chrono>

namespace fs = std::filesystem;

namespace ft {
namespace server {

ServerCore::ServerCore() 
    : config_(),
      listen_socket_(nullptr),
      accept_thread_(),
      session_manager_thread_(),
      running_(false) {
}

ServerCore::~ServerCore() {
    stop();
}

bool ServerCore::initialize(const ServerConfig& config, utils::LogLevel log_level) {
    // 初始化日志系统
    if (!utils::Logger::instance().init(log_level)) {
        std::cerr << "Failed to initialize logger" << std::endl;
        return false;
    }
    
    config_ = config;
    storage_path_ = config.storage_path;
    
    // 创建存储目录
    try {
        if (!fs::exists(storage_path_)) {
            if (!fs::create_directories(storage_path_)) {
                LOG_ERROR("Failed to create storage directory: %s", storage_path_.c_str());
                return false;
            }
        }
    } catch (const std::exception& e) {
        LOG_ERROR("Exception while creating storage directory: %s", e.what());
        return false;
    }
    
    // 初始化用户管理器
    std::string users_file = "data/auth/users.json";
    std::string api_keys_file = "data/auth/api_keys.json";
    
    // 确保认证数据目录存在
    try {
        if (!fs::exists("data/auth")) {
            if (!fs::create_directories("data/auth")) {
                LOG_ERROR("Failed to create auth data directory: data/auth");
                return false;
            }
        }
    } catch (const std::exception& e) {
        LOG_ERROR("Exception while creating auth data directory: %s", e.what());
        return false;
    }
    
    if (!utils::UserManager::instance().initialize(users_file, api_keys_file)) {
        LOG_ERROR("Failed to initialize UserManager");
        return false;
    }
    
    // 初始化会话管理器
    SessionManager::instance().set_max_sessions(config.max_connections);
    
    return true;
}

bool ServerCore::start() {
    if (running_) {
        LOG_WARNING("Server is already running");
        return false;
    }
    
    // 创建监听socket
    listen_socket_ = std::make_unique<network::TcpSocket>();
    
    // 绑定地址
    network::SocketError err = listen_socket_->bind(config_.bind_address, config_.port);
    if (err != network::SocketError::SUCCESS) {
        LOG_ERROR("Failed to bind to %s:%d, error: %d", 
                 config_.bind_address.c_str(), config_.port, static_cast<int>(err));
        return false;
    }
    
    // 开始监听
    err = listen_socket_->listen(config_.max_connections);
    if (err != network::SocketError::SUCCESS) {
        LOG_ERROR("Failed to listen on %s:%d, error: %d", 
                 config_.bind_address.c_str(), config_.port, static_cast<int>(err));
        return false;
    }
    
    LOG_INFO("Server started on %s:%d", config_.bind_address.c_str(), config_.port);
    
    // 标记为运行状态
    running_ = true;
    
    // 启动接受连接线程
    accept_thread_ = std::thread(&ServerCore::accept_thread, this);
    
    // 启动会话管理线程
    session_manager_thread_ = std::thread(&ServerCore::session_manager_thread, this);
    
    return true;
}

void ServerCore::stop() {
    if (!running_) {
        return;
    }
    
    LOG_INFO("Stopping server...");
    
    // 标记停止状态
    running_ = false;
    
    // 关闭监听socket以中断accept
    if (listen_socket_) {
        listen_socket_->close();
        listen_socket_.reset();
    }
    
    // 等待接受连接线程结束
    if (accept_thread_.joinable()) {
        accept_thread_.join();
    }
    
    // 等待会话管理线程结束
    if (session_manager_thread_.joinable()) {
        session_manager_thread_.join();
    }
    
    // 关闭所有会话
    SessionManager::instance().close_all_sessions();
    
    LOG_INFO("Server stopped");
    
    // 通知等待的线程
    {
        std::lock_guard<std::mutex> lock(stop_mutex_);
        stop_cv_.notify_all();
    }
}

bool ServerCore::is_running() const {
    return running_;
}

void ServerCore::wait() {
    std::unique_lock<std::mutex> lock(stop_mutex_);
    stop_cv_.wait(lock, [this] { return !running_; });
}

size_t ServerCore::get_session_count() const {
    return SessionManager::instance().get_session_count();
}

void ServerCore::accept_thread() {
    LOG_INFO("Accept thread started");
    
    while (running_) {
        // 创建临时socket接收新连接
        network::TcpSocket client_socket;
        
        // 接受新的连接
        network::SocketError err = listen_socket_->accept(client_socket);
        if (err != network::SocketError::SUCCESS) {
            if (running_) {
                LOG_ERROR("Failed to accept connection, error: %d", static_cast<int>(err));
                std::this_thread::sleep_for(std::chrono::seconds(1));
            }
            continue;
        }
        
        // 设置socket选项
        client_socket.set_recv_timeout(std::chrono::seconds(3));
        client_socket.set_send_timeout(std::chrono::seconds(3));
        
        // 记录连接信息
        LOG_INFO("New connection from %s:%d", 
                 client_socket.get_remote_address().c_str(), 
                 client_socket.get_remote_port());
        
        int socket_fd = client_socket.get_fd();
        if (socket_fd < 0) {
            LOG_ERROR("Invalid socket file descriptor: %d", socket_fd);
            continue;
        }
        
        // 创建客户端会话
        LOG_DEBUG("Creating ClientSession with socket fd=%d", socket_fd);
        std::shared_ptr<ClientSession> session = std::make_shared<ClientSession>(
            std::make_unique<network::TcpSocket>(std::move(client_socket)));
        
        // 检查session的socket是否有效
        LOG_DEBUG("Created ClientSession - id=%zu, client=%s", 
                 session->get_session_id(), 
                 session->get_client_address().c_str());
        
        // 使用会话管理器添加会话
        if (SessionManager::instance().add_session(session) == 0) {
            LOG_WARNING("Failed to add session to SessionManager, max sessions may be reached");
            continue;
        }
        
        // 启动会话线程
        LOG_DEBUG("Starting session %zu", session->get_session_id());
        session->start();
    }
    
    LOG_INFO("Accept thread exiting");
}

void ServerCore::session_manager_thread() {
    LOG_INFO("Session manager thread started");
    
    while (running_) {
        // 定时清理过期会话
        std::this_thread::sleep_for(std::chrono::seconds(5));
        SessionManager::instance().clean_expired_sessions();
        
        LOG_DEBUG("Current active sessions: %zu", SessionManager::instance().get_session_count());
    }
    
    LOG_INFO("Session manager thread exiting");
}

// 静态成员初始化
std::string ServerCore::storage_path_;

} // namespace server
} // namespace ft 