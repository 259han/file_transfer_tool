#pragma once

#include <string>
#include <vector>
#include <chrono>
#include <memory>
#include "socket_error.h"

namespace ft {
namespace network {

// TCP套接字选项
struct SocketOptions {
    // 连接超时
    std::chrono::milliseconds connect_timeout;
    
    // 接收超时
    std::chrono::milliseconds recv_timeout;
    
    // 发送超时
    std::chrono::milliseconds send_timeout;
    
    // 保活选项
    bool keep_alive;
    int keep_idle;      // 空闲时间（秒）
    int keep_interval;  // 探测间隔（秒）
    int keep_count;     // 探测次数
    
    // 缓冲区大小
    int recv_buffer_size;
    int send_buffer_size;
    
    // 地址和端口重用
    bool reuse_address;
    bool reuse_port;
    
    // 非阻塞模式
    bool non_blocking;
    
    // 构造函数设置默认值
    SocketOptions();
};

// TCP套接字类
class TcpSocket {
public:
    // 构造函数
    explicit TcpSocket(const SocketOptions& options = SocketOptions());
    
    // 析构函数
    ~TcpSocket();
    
    // 禁用拷贝构造和赋值
    TcpSocket(const TcpSocket&) = delete;
    TcpSocket& operator=(const TcpSocket&) = delete;
    
    // 移动构造和赋值
    TcpSocket(TcpSocket&& other) noexcept;
    TcpSocket& operator=(TcpSocket&& other) noexcept;
    
    // 连接到服务器
    SocketError connect(const std::string& host, uint16_t port);
    
    // 绑定到本地地址
    SocketError bind(const std::string& ip, uint16_t port);
    
    // 开始监听
    SocketError listen(int backlog = 128);
    
    // 接受连接
    std::unique_ptr<TcpSocket> accept();
    
    // 关闭连接
    void close();
    
    // 发送数据（确保全部发送）
    SocketError send_all(const void* data, size_t len);
    
    // 接收数据（确保全部接收）
    SocketError recv_all(void* buffer, size_t len);
    
    // 发送单个数据包
    SocketError send(const void* data, size_t len, size_t& sent);
    
    // 接收单个数据包
    SocketError recv(void* buffer, size_t len, size_t& received);
    
    // 设置接收超时
    void set_recv_timeout(std::chrono::milliseconds timeout);
    
    // 零拷贝发送文件（Linux sendfile系统调用）
    SocketError sendfile_zero_copy(int file_fd, off_t offset, size_t count, size_t& sent);
    
    // 零拷贝发送内存映射文件
    SocketError send_mmap_zero_copy(void* mmap_addr, size_t len);
    
    // 设置非阻塞模式
    bool set_non_blocking(bool non_blocking);
    
    // 获取本地地址信息
    std::string get_local_ip() const { return local_ip_; }
    uint16_t get_local_port() const { return local_port_; }
    
    // 获取远程地址信息
    std::string get_remote_ip() const { return remote_ip_; }
    uint16_t get_remote_port() const { return remote_port_; }
    
    // 获取最后一个错误
    SocketError get_last_error() const { return last_error_; }
    
    // 检查是否已连接
    bool is_connected() const;
    
    // 获取底层文件描述符
    int get_fd() const { return sockfd_; }
    
    // 应用套接字选项
    void apply_socket_options();
    
private:
    // 更新本地地址信息
    void update_local_address();
    
    // 更新远程地址信息
    void update_remote_address();
    
    // 底层文件描述符
    int sockfd_;
    
    // 套接字选项
    SocketOptions options_;
    
    // 连接状态
    bool connected_;
    
    // 本地地址信息
    std::string local_ip_;
    uint16_t local_port_;
    
    // 远程地址信息
    std::string remote_ip_;
    uint16_t remote_port_;
    
    // 最后一个错误
    SocketError last_error_;
};

} // namespace network
} // namespace ft