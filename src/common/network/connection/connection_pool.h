#pragma once

#include "../socket/tcp_socket.h"
#include <vector>
#include <mutex>
#include <memory>

namespace ft {
namespace network {

/**
 * @brief 连接池类
 */
class ConnectionPool {
public:
    /**
     * @brief 获取单例实例
     * @return 连接池实例
     */
    static ConnectionPool& instance();
    
    /**
     * @brief 连接到服务器
     * @param host 主机地址
     * @param port 端口号
     * @return 连接对象
     */
    std::shared_ptr<TcpSocket> connect(const std::string& host, uint16_t port);
    
    /**
     * @brief 释放连接
     * @param socket 连接对象
     */
    void release(std::shared_ptr<TcpSocket> socket);
    
private:
    /**
     * @brief 构造函数
     */
    ConnectionPool();
    
    /**
     * @brief 析构函数
     */
    ~ConnectionPool();
    
private:
    std::vector<std::shared_ptr<TcpSocket>> idle_connections_;
    std::mutex mutex_;
};

} // namespace network
} // namespace ft 