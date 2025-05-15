#pragma once

#include <string>
#include <chrono>
#include <vector>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

namespace ft {
namespace network {

/**
 * @brief Socket错误代码
 */
enum class SocketError {
    SUCCESS = 0,          // 成功
    SOCKET_CREATE_FAILED, // 创建socket失败
    BIND_FAILED,          // 绑定失败
    LISTEN_FAILED,        // 监听失败
    CONNECT_FAILED,       // 连接失败
    ACCEPT_FAILED,        // 接受连接失败
    SEND_FAILED,          // 发送失败
    RECV_FAILED,          // 接收失败
    TIMEOUT,              // 超时
    CLOSED,               // 连接已关闭
    INVALID_STATE,        // 无效状态
    INVALID_ARGUMENT,     // 无效参数
    UNKNOWN               // 未知错误
};

/**
 * @brief Socket选项
 */
struct SocketOptions {
    bool reuse_address;                        // 重用地址
    bool keep_alive;                           // 保活
    bool non_blocking;                         // 非阻塞
    int send_buffer_size;                      // 发送缓冲区大小
    int recv_buffer_size;                      // 接收缓冲区大小
    std::chrono::milliseconds connect_timeout; // 连接超时
    std::chrono::milliseconds send_timeout;    // 发送超时
    std::chrono::milliseconds recv_timeout;    // 接收超时
    
    SocketOptions()
        : reuse_address(true),
          keep_alive(true),
          non_blocking(false),
          send_buffer_size(64 * 1024),
          recv_buffer_size(64 * 1024),
          connect_timeout(10000),
          send_timeout(10000),
          recv_timeout(30000) {
    }
};

/**
 * @brief TCP Socket类
 */
class TcpSocket {
public:
    /**
     * @brief 构造函数
     * @param options Socket选项
     */
    explicit TcpSocket(const SocketOptions& options = SocketOptions());
    
    /**
     * @brief 从已有的套接字创建TcpSocket
     * @param sockfd 套接字描述符
     * @param options Socket选项
     */
    TcpSocket(int sockfd, const SocketOptions& options = SocketOptions());
    
    /**
     * @brief 复制构造函数 - 仅对已连接的socket进行拷贝
     * @param other 要复制的TcpSocket对象
     */
    TcpSocket(const TcpSocket& other);
    
    /**
     * @brief 赋值运算符 - 实现深拷贝
     * @param other 要赋值的TcpSocket对象
     * @return TcpSocket引用
     */
    TcpSocket& operator=(const TcpSocket& other);
    
    /**
     * @brief 移动构造函数
     * @param other 要移动的TcpSocket对象
     */
    TcpSocket(TcpSocket&& other) noexcept;
    
    /**
     * @brief 移动赋值运算符
     * @param other 要移动赋值的TcpSocket对象
     * @return TcpSocket引用
     */
    TcpSocket& operator=(TcpSocket&& other) noexcept;
    
    /**
     * @brief 析构函数
     */
    ~TcpSocket();
    
    /**
     * @brief 绑定地址和端口
     * @param host 主机地址
     * @param port 端口
     * @return 错误代码
     */
    SocketError bind(const std::string& host, uint16_t port);
    
    /**
     * @brief 开始监听
     * @param backlog 等待队列大小
     * @return 错误代码
     */
    SocketError listen(int backlog = 5);
    
    /**
     * @brief 接受连接
     * @param client_socket 接受的客户端socket
     * @return 错误代码
     */
    SocketError accept(TcpSocket& client_socket);
    
    /**
     * @brief 连接到服务器
     * @param host 服务器地址
     * @param port 服务器端口
     * @return 错误代码
     */
    SocketError connect(const std::string& host, uint16_t port);
    
    /**
     * @brief 发送数据
     * @param data 数据指针
     * @param len 数据长度
     * @param sent_len 发送的字节数
     * @return 错误代码
     */
    SocketError send(const void* data, size_t len, size_t& sent_len);
    
    /**
     * @brief 接收数据
     * @param buffer 缓冲区指针
     * @param len 缓冲区大小
     * @param received_len 接收的字节数
     * @return 错误代码
     */
    SocketError recv(void* buffer, size_t len, size_t& received_len);
    
    /**
     * @brief 发送所有数据
     * @param data 数据指针
     * @param len 数据长度
     * @return 错误代码
     */
    SocketError send_all(const void* data, size_t len);
    
    /**
     * @brief 接收指定大小的数据
     * @param buffer 缓冲区指针
     * @param len 需要接收的字节数
     * @return 错误代码
     */
    SocketError recv_all(void* buffer, size_t len);
    
    /**
     * @brief 关闭套接字
     */
    void close();
    
    /**
     * @brief 获取套接字描述符
     * @return 套接字描述符
     */
    int get_fd() const;
    
    /**
     * @brief 获取本地地址
     * @return 本地地址
     */
    std::string get_local_address() const;
    
    /**
     * @brief 获取本地端口
     * @return 本地端口
     */
    uint16_t get_local_port() const;
    
    /**
     * @brief 获取远程地址
     * @return 远程地址
     */
    std::string get_remote_address() const;
    
    /**
     * @brief 获取远程端口
     * @return 远程端口
     */
    uint16_t get_remote_port() const;
    
    /**
     * @brief 是否已连接
     * @return 是否已连接
     */
    bool is_connected() const;
    
    /**
     * @brief 设置非阻塞模式
     * @param non_blocking 是否非阻塞
     */
    void set_non_blocking(bool non_blocking);
    
    /**
     * @brief 设置接收超时
     * @param timeout 超时时间
     */
    void set_recv_timeout(const std::chrono::milliseconds& timeout);
    
    /**
     * @brief 设置发送超时
     * @param timeout 超时时间
     */
    void set_send_timeout(const std::chrono::milliseconds& timeout);
    
private:
    /**
     * @brief 应用socket选项
     */
    void apply_socket_options();
    
    /**
     * @brief 获取socket地址信息
     * @param addr 地址结构体
     * @param ip 输出IP地址
     * @param port 输出端口
     */
    static void get_socket_address(const struct sockaddr_in& addr, std::string& ip, uint16_t& port);
    
    /**
     * @brief 内部检查连接状态，非const方法，可以更新connected_状态
     * @return 是否已连接
     */
    bool check_connection_state_();
    
private:
    int sockfd_;
    SocketOptions options_;
    bool connected_;
    std::string local_ip_;
    uint16_t local_port_;
    std::string remote_ip_;
    uint16_t remote_port_;
};

} // namespace network
} // namespace ft 