#include "session_manager.h"
#include "../../common/utils/logging/logger.h"
#include "../core/server_core.h"
#include <thread>

namespace ft {
namespace server {

// 初始化静态成员
std::atomic<size_t> SessionManager::next_session_id_(1);

SessionManager& SessionManager::instance() {
    static SessionManager instance;
    return instance;
}

SessionManager::SessionManager()
    : sessions_(),
      mutex_(),
      max_sessions_(100) {
}

SessionManager::~SessionManager() {
    close_all_sessions();
}

size_t SessionManager::add_session(std::shared_ptr<ClientSession> session) {
    if (!session) {
        return 0;
    }
    
    std::lock_guard<std::mutex> lock(mutex_);
    
    // 检查是否超过最大会话数
    size_t max_sessions = max_sessions_; // 使用普通变量
    if (sessions_.size() >= max_sessions) {
        LOG_WARNING("Max sessions reached: %zu", max_sessions);
        return 0;
    }
    
    // 分配会话ID
    size_t session_id = next_session_id_++;
    
    // 添加到会话列表
    sessions_[session_id] = session;
    
    LOG_INFO("Session added: %zu, total: %zu", session_id, sessions_.size());
    
    return session_id;
}

bool SessionManager::remove_session(size_t session_id) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    auto it = sessions_.find(session_id);
    if (it != sessions_.end()) {
        sessions_.erase(it);
        LOG_INFO("Session removed: %zu, total: %zu", session_id, sessions_.size());
        return true;
    }
    
    return false;
}

std::shared_ptr<ClientSession> SessionManager::get_session(size_t session_id) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    auto it = sessions_.find(session_id);
    if (it != sessions_.end()) {
        return it->second;
    }
    
    return nullptr;
}

size_t SessionManager::get_session_count() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return sessions_.size();
}

void SessionManager::clean_expired_sessions() {
    std::lock_guard<std::mutex> lock(mutex_);
    
    size_t removed = 0;
    
    for (auto it = sessions_.begin(); it != sessions_.end();) {
        auto session = it->second;
        
        // 检查会话是否已断开连接
        if (!session->is_connected()) {
            LOG_INFO("Removing expired session: %zu", session->get_session_id());
            it = sessions_.erase(it);
            removed++;
        } else {
            ++it;
        }
    }
    
    if (removed > 0 || !sessions_.empty()) {
        LOG_DEBUG("Cleaned expired sessions, total: %zu", sessions_.size());
    }
}

void SessionManager::close_all_sessions() {
    std::lock_guard<std::mutex> lock(mutex_);
    
    LOG_INFO("Closing all sessions: %zu", sessions_.size());
    
    // 创建一个临时副本，避免在循环中修改容器
    auto sessions_copy = sessions_;
    
    // 先停止所有会话
    for (auto& pair : sessions_copy) {
        pair.second->stop();
    }
    
    // 清空会话容器
    sessions_.clear();
    
    LOG_INFO("All sessions closed");
}

void SessionManager::set_max_sessions(size_t max_sessions) {
    max_sessions_ = max_sessions;
}

size_t SessionManager::get_max_sessions() const {
    size_t max_sessions = max_sessions_; // 使用普通变量
    return max_sessions;
}

bool SessionManager::can_create_session() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return sessions_.size() < max_sessions_;
}

} // namespace server
} // namespace ft 