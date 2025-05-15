#pragma once

#include <memory>
#include <functional>
#include <thread>
#include <atomic>
#include "../../common/network/socket/tcp_socket.h"

namespace ft {
namespace server {

/**
 * @brief 连接事件类型
 */
enum class ConnectionEvent {
    CONNECTED,      // 连接建立
    DISCONNECTED,   // 连接断开
    DATA_RECEIVED,  // 收到数据
    ERROR           // 发生错误
};

/**
 * @brief 连接处理器类
 */
class ConnectionHandler {
public:
    /**
     * @brief 构造函数
     * @param socket 客户端socket
     */
    explicit ConnectionHandler(std::unique_ptr<network::TcpSocket> socket);
    
    /**
     * @brief 析构函数
     */
    ~ConnectionHandler();
    
    /**
     * @brief 启动处理
     */
    void start();
    
    /**
     * @brief 停止处理
     */
    void stop();
    
    /**
     * @brief 发送数据
     * @param data 数据指针
     * @param len 数据长度
     * @return 是否发送成功
     */
    bool send(const void* data, size_t len);
    
    /**
     * @brief 获取客户端地址
     * @return 客户端地址
     */
    std::string get_client_address() const;
    
    /**
     * @brief 是否已连接
     * @return 是否已连接
     */
    bool is_connected() const;
    
    /**
     * @brief 设置连接事件回调
     * @param callback 回调函数
     */
    void set_event_callback(std::function<void(ConnectionEvent, const void*, size_t)> callback);
    
private:
    /**
     * @brief 接收线程
     */
    void receive_thread();
    
private:
    std::unique_ptr<network::TcpSocket> socket_;
    std::thread thread_;
    std::atomic<bool> running_;
    std::function<void(ConnectionEvent, const void*, size_t)> event_callback_;
};

} // namespace server
} // namespace ft 