#pragma once

#include <unordered_map>
#include <mutex>
#include <memory>
#include <atomic>
#include <functional>
#include "../../common/network/socket/tcp_socket.h"

namespace ft {
namespace server {

// 前向声明
class ClientSession;

/**
 * @brief 会话管理器类
 */
class SessionManager {
public:
    /**
     * @brief 获取单例实例
     * @return 会话管理器实例
     */
    static SessionManager& instance();
    
    /**
     * @brief 添加会话
     * @param session 客户端会话
     * @return 会话ID
     */
    size_t add_session(std::shared_ptr<ClientSession> session);
    
    /**
     * @brief 移除会话
     * @param session_id 会话ID
     * @return 是否移除成功
     */
    bool remove_session(size_t session_id);
    
    /**
     * @brief 获取会话
     * @param session_id 会话ID
     * @return 会话对象
     */
    std::shared_ptr<ClientSession> get_session(size_t session_id);
    
    /**
     * @brief 获取会话数量
     * @return 会话数量
     */
    size_t get_session_count() const;
    
    /**
     * @brief 清理过期会话
     */
    void clean_expired_sessions();
    
    /**
     * @brief 关闭所有会话
     */
    void close_all_sessions();
    
    /**
     * @brief 设置最大会话数
     * @param max_sessions 最大会话数
     */
    void set_max_sessions(size_t max_sessions);
    
    /**
     * @brief 获取最大会话数
     * @return 最大会话数
     */
    size_t get_max_sessions() const;
    
    /**
     * @brief 判断是否可以创建新会话
     * @return 是否可以创建新会话
     */
    bool can_create_session() const;
    
private:
    /**
     * @brief 构造函数
     */
    SessionManager();
    
    /**
     * @brief 析构函数
     */
    ~SessionManager();
    
private:
    std::unordered_map<size_t, std::shared_ptr<ClientSession>> sessions_;
    mutable std::mutex mutex_;
    std::atomic<size_t> max_sessions_;
    static std::atomic<size_t> next_session_id_;
};

} // namespace server
} // namespace ft 