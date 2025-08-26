#include "tcp_socket.h"
#include <unistd.h>
#include <fcntl.h>
#include <netdb.h>
#include <errno.h>
#include <cstring>
#include <stdexcept>
#include <poll.h>
#include <thread>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#ifdef __linux__
#include <sys/sendfile.h>
#endif
#include "../../utils/logging/logger.h"

namespace ft {
namespace network {

// 优化的TCP Socket选项
SocketOptions::SocketOptions()
    : connect_timeout(std::chrono::seconds(10)),
      recv_timeout(std::chrono::seconds(30)),
      send_timeout(std::chrono::seconds(30)),
      keep_alive(true),
      keep_idle(30),            // 30秒后开始探测（优化：从60秒减少到30秒）
      keep_interval(5),         // 每5秒探测一次
      keep_count(3),            // 探测3次无响应则认为连接断开
      recv_buffer_size(1024 * 1024),  // 1MB（优化：从256KB增加到1MB）
      send_buffer_size(1024 * 1024),  // 1MB（优化：从256KB增加到1MB）
      reuse_address(true),
      reuse_port(true),         // 优化：启用端口复用，提高多进程/线程性能
      non_blocking(false) {     // 默认阻塞模式，避免复杂性
}

TcpSocket::TcpSocket(const SocketOptions& options)
    : sockfd_(-1),
      options_(options),
      connected_(false),
      local_ip_(""),
      local_port_(0),
      remote_ip_(""),
      remote_port_(0),
      last_error_(SocketError::SUCCESS) {
    
    // 创建套接字
    sockfd_ = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd_ < 0) {
        last_error_ = SocketError::SOCKET_CREATE_FAILED;
        LOG_ERROR("Failed to create socket: %s (errno=%d)", strerror(errno), errno);
        return;
    }
    
    // 应用套接字选项
    apply_socket_options();
}

TcpSocket::TcpSocket(TcpSocket&& other) noexcept
    : sockfd_(other.sockfd_),
      options_(std::move(other.options_)),
      connected_(other.connected_),
      local_ip_(std::move(other.local_ip_)),
      local_port_(other.local_port_),
      remote_ip_(std::move(other.remote_ip_)),
      remote_port_(other.remote_port_),
      last_error_(other.last_error_) {
    
    // 防止源对象析构时关闭socket
    other.sockfd_ = -1;
    other.connected_ = false;
    other.local_port_ = 0;
    other.remote_port_ = 0;
}

TcpSocket& TcpSocket::operator=(TcpSocket&& other) noexcept {
    if (this != &other) {
        // 关闭现有套接字
        if (sockfd_ >= 0) {
            ::close(sockfd_);
        }
      
        // 移动所有资源
        sockfd_ = other.sockfd_;
        options_ = std::move(other.options_);
        connected_ = other.connected_;
        local_ip_ = std::move(other.local_ip_);
        local_port_ = other.local_port_;
        remote_ip_ = std::move(other.remote_ip_);
        remote_port_ = other.remote_port_;
        last_error_ = other.last_error_;
        
        // 防止源对象析构时关闭socket
        other.sockfd_ = -1;
        other.connected_ = false;
        other.local_port_ = 0;
        other.remote_port_ = 0;
    }
    return *this;
}

TcpSocket::~TcpSocket() {
    close();
}

SocketError TcpSocket::bind(const std::string& host, uint16_t port) {
    if (sockfd_ < 0) {
        last_error_ = SocketError::INVALID_STATE;
        return last_error_;
    }
    
    struct sockaddr_in addr;
    std::memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    
    if (host.empty() || host == "0.0.0.0") {
        addr.sin_addr.s_addr = htonl(INADDR_ANY);
    } else {
        if (inet_pton(AF_INET, host.c_str(), &addr.sin_addr) <= 0) {
            last_error_ = SocketError::INVALID_ARGUMENT;
            return last_error_;
        }
    }
    
    if (::bind(sockfd_, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        last_error_ = SocketError::BIND_FAILED;
        LOG_ERROR("Bind failed: %s (errno=%d)", strerror(errno), errno);
        return last_error_;
    }
    
    // 保存本地地址信息
    local_ip_ = host.empty() ? "0.0.0.0" : host;
    local_port_ = port;
    
    last_error_ = SocketError::SUCCESS;
    return last_error_;
}

SocketError TcpSocket::listen(int backlog) {
    if (sockfd_ < 0) {
        last_error_ = SocketError::INVALID_STATE;
        return last_error_;
    }
    
    if (::listen(sockfd_, backlog) < 0) {
        last_error_ = SocketError::LISTEN_FAILED;
        LOG_ERROR("Listen failed: %s (errno=%d)", strerror(errno), errno);
        return last_error_;
    }
    
    last_error_ = SocketError::SUCCESS;
    return last_error_;
}

std::unique_ptr<TcpSocket> TcpSocket::accept() {
    if (sockfd_ < 0) {
        last_error_ = SocketError::INVALID_STATE;
        return nullptr;
    }
    
    struct sockaddr_in addr;
    socklen_t addr_len = sizeof(addr);
            
    int client_fd = ::accept(sockfd_, (struct sockaddr*)&addr, &addr_len);
    if (client_fd < 0) {
        last_error_ = SocketError::ACCEPT_FAILED;
        LOG_ERROR("Accept failed: %s (errno=%d)", strerror(errno), errno);
        return nullptr;
    }
    
    // 创建客户端套接字
    auto client_socket = std::make_unique<TcpSocket>(options_);
    
    // 关闭新创建的socket描述符，使用accept返回的
    if (client_socket->sockfd_ >= 0) {
        ::close(client_socket->sockfd_);
    }
    
    // 设置客户端套接字状态
    client_socket->sockfd_ = client_fd;
    client_socket->connected_ = true;
    
    // 获取客户端地址信息
    char ip_buf[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &addr.sin_addr, ip_buf, sizeof(ip_buf));
    client_socket->remote_ip_ = ip_buf;
    client_socket->remote_port_ = ntohs(addr.sin_port);
    client_socket->local_ip_ = local_ip_;
    client_socket->local_port_ = local_port_;
    
    // 应用套接字选项到客户端连接
    client_socket->apply_socket_options();
    
    LOG_INFO("Accepted connection from %s:%d", 
             client_socket->remote_ip_.c_str(), client_socket->remote_port_);
    
    last_error_ = SocketError::SUCCESS;
    return client_socket;
}

SocketError TcpSocket::connect(const std::string& host, uint16_t port) {
    if (sockfd_ < 0) {
        last_error_ = SocketError::INVALID_STATE;
        return last_error_;
    }
    
    // 如果已经连接，先关闭现有连接
    if (connected_) {
        close();
        
        // 重新创建socket
        sockfd_ = socket(AF_INET, SOCK_STREAM, 0);
        if (sockfd_ < 0) {
            last_error_ = SocketError::SOCKET_CREATE_FAILED;
            LOG_ERROR("Failed to create new socket: %s (errno=%d)", strerror(errno), errno);
            return last_error_;
        }
        
        // 应用套接字选项
        apply_socket_options();
    }
    
    // 解析服务器地址
    struct sockaddr_in addr;
    std::memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    
    // 尝试将主机名解析为IP地址
    if (inet_pton(AF_INET, host.c_str(), &addr.sin_addr) != 1) {
        // 如果不是IP地址，尝试通过域名解析
        struct hostent* he = gethostbyname(host.c_str());
        if (!he) {
            last_error_ = SocketError::CONNECT_FAILED;
            LOG_ERROR("Failed to resolve hostname %s", host.c_str());
            return last_error_;
        }
        
        // 复制解析出的地址
        std::memcpy(&addr.sin_addr, he->h_addr, he->h_length);
    }
    
    // 设置为非阻塞模式进行连接
    int flags = fcntl(sockfd_, F_GETFL, 0);
    fcntl(sockfd_, F_SETFL, flags | O_NONBLOCK);
    
    // 尝试连接
    int ret = ::connect(sockfd_, (struct sockaddr*)&addr, sizeof(addr));
    
    // 连接立即成功或者正在进行中
    if (ret == 0 || (ret < 0 && errno == EINPROGRESS)) {
        // 使用poll等待连接完成
        struct pollfd pfd;
        pfd.fd = sockfd_;
        pfd.events = POLLOUT;
        pfd.revents = 0;
        
        // 转换超时时间为毫秒
        int timeout_ms = static_cast<int>(options_.connect_timeout.count());
        
        // 等待连接完成或者超时
        ret = poll(&pfd, 1, timeout_ms);
        
        // 恢复原来的阻塞模式
        fcntl(sockfd_, F_SETFL, flags);
        
        if (ret < 0) {
            last_error_ = SocketError::CONNECT_FAILED;
            LOG_ERROR("Poll error during connect: %s (errno=%d)", strerror(errno), errno);
            return last_error_;
        } else if (ret == 0) {
            last_error_ = SocketError::TIMEOUT;
            LOG_ERROR("Timeout connecting to %s:%d", host.c_str(), port);
            return last_error_;
        } else {
            // 检查socket是否有错误
            if (pfd.revents & (POLLERR | POLLHUP | POLLNVAL)) {
                int err;
                socklen_t err_len = sizeof(err);
                getsockopt(sockfd_, SOL_SOCKET, SO_ERROR, &err, &err_len);
                
                last_error_ = SocketError::CONNECT_FAILED;
                LOG_ERROR("Failed to connect to %s:%d: %s (errno=%d)", host.c_str(), port, strerror(err), err);
                return last_error_;
            }
            
            // 连接成功
            connected_ = true;
            remote_ip_ = host;
            remote_port_ = port;
            
            // 更新本地地址信息
            update_local_address();
            
            LOG_INFO("Connected to %s:%d from local %s:%d", 
                     host.c_str(), port, local_ip_.c_str(), local_port_);
            
            last_error_ = SocketError::SUCCESS;
            return last_error_;
        }
    } else {
        // 恢复原来的阻塞模式
        fcntl(sockfd_, F_SETFL, flags);
        
        last_error_ = SocketError::CONNECT_FAILED;
        LOG_ERROR("Failed to connect to %s:%d: %s (errno=%d)", host.c_str(), port, strerror(errno), errno);
        return last_error_;
    }
}

SocketError TcpSocket::send(const void* data, size_t len, size_t& sent_len) {
    if (sockfd_ < 0 || !connected_) {
        last_error_ = SocketError::INVALID_STATE;
        return last_error_;
    }
    
    if (!data || len == 0) {
        last_error_ = SocketError::INVALID_ARGUMENT;
        return last_error_;
    }
    
    // 尝试发送数据
    ssize_t ret = ::send(sockfd_, data, len, MSG_NOSIGNAL);
    if (ret < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            sent_len = 0;
            last_error_ = SocketError::TIMEOUT;
            return last_error_;
        } else if (errno == EPIPE || errno == ECONNRESET) {
            connected_ = false;
            last_error_ = SocketError::CLOSED;
            return last_error_;
        } else {
            last_error_ = SocketError::SEND_FAILED;
            LOG_ERROR("Send failed: %s (errno=%d)", strerror(errno), errno);
            return last_error_;
        }
    }
    
    sent_len = static_cast<size_t>(ret);
    last_error_ = SocketError::SUCCESS;
    return last_error_;
}

SocketError TcpSocket::recv(void* buffer, size_t len, size_t& received_len) {
    if (sockfd_ < 0 || !connected_) {
        last_error_ = SocketError::INVALID_STATE;
        return last_error_;
    }
    
    if (!buffer || len == 0) {
        last_error_ = SocketError::INVALID_ARGUMENT;
        return last_error_;
    }
    
    // 尝试接收数据
    ssize_t ret = ::recv(sockfd_, buffer, len, 0);
    if (ret < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            received_len = 0;
            last_error_ = SocketError::TIMEOUT;
            return last_error_;
        } else if (errno == ECONNRESET) {
            connected_ = false;
            last_error_ = SocketError::CLOSED;
            return last_error_;
        } else {
            last_error_ = SocketError::RECV_FAILED;
            LOG_ERROR("Recv failed: %s (errno=%d)", strerror(errno), errno);
            return last_error_;
        }
    } else if (ret == 0) {
        // 对端关闭连接
        connected_ = false;
        last_error_ = SocketError::CLOSED;
        return last_error_;
    }
    
    received_len = static_cast<size_t>(ret);
    last_error_ = SocketError::SUCCESS;
    return last_error_;
}

SocketError TcpSocket::send_all(const void* data, size_t len) {
    if (sockfd_ < 0) {
        last_error_ = SocketError::INVALID_STATE;
        return last_error_;
    }
    
    if (!data || len == 0) {
        last_error_ = SocketError::INVALID_ARGUMENT;
        return last_error_;
    }
    
    // 使用偏移量跟踪已发送的数据
    size_t total_sent = 0;
    const uint8_t* buffer = static_cast<const uint8_t*>(data);
    
    // 记录开始时间用于超时检测
    auto start_time = std::chrono::steady_clock::now();
    
    // 计算总超时时间 (原超时时间的1.5倍，考虑到重试)
    auto total_timeout_ms = options_.send_timeout.count() * 1.5;
    
    // 最大重试次数和延迟
    const int max_retries = 5;
    int retry_count = 0;
    
    // 优化：使用批量发送，减少系统调用次数
    const size_t optimal_batch_size = 64 * 1024;  // 64KB
    
    while (total_sent < len) {
        // 计算当前已用时间
        auto current_time = std::chrono::steady_clock::now();
        auto elapsed_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
            current_time - start_time).count();
        
        // 检查是否超时
        if (elapsed_ms > total_timeout_ms) {
            last_error_ = SocketError::TIMEOUT;
            LOG_ERROR("send_all timeout after %lld ms", elapsed_ms);
            return last_error_;
        }
        
        // 检查socket是否有效
        if (sockfd_ < 0 || !connected_) {
            last_error_ = SocketError::INVALID_STATE;
            return last_error_;
        }
        
        // 计算当前批次大小
        size_t batch_size = len - total_sent;
        if (batch_size > optimal_batch_size) {
            batch_size = optimal_batch_size;
        }
        
        // 尝试发送数据
        ssize_t sent = ::send(sockfd_, buffer + total_sent, batch_size, MSG_NOSIGNAL);
        
        if (sent < 0) {
            if (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK) {
                retry_count++;
                if (retry_count > max_retries) {
                    last_error_ = SocketError::TIMEOUT;
                    return last_error_;
                }
                // 短暂休眠后继续，使用指数退避策略
                std::this_thread::sleep_for(std::chrono::milliseconds(50 * (1 << retry_count)));
                continue;
            } else if (errno == EPIPE || errno == ECONNRESET || errno == ECONNABORTED) {
                // 连接被对端关闭
                last_error_ = SocketError::CLOSED;
                connected_ = false;
                LOG_ERROR("send_all: connection closed by peer: %s (errno=%d)", strerror(errno), errno);
                return last_error_;
            } else {
                // 其他错误视为严重错误
                last_error_ = SocketError::SEND_FAILED;
                LOG_ERROR("send_all: send failed: %s (errno=%d)", strerror(errno), errno);
                return last_error_;
            }
        } else if (sent == 0) {
            // 发送0字节通常意味着连接已关闭
            last_error_ = SocketError::CLOSED;
            connected_ = false;
            return last_error_;
        }
        
        // 更新已发送字节数
        total_sent += sent;
        
        // 成功发送数据后重置重试计数
        retry_count = 0;
    }
    
    // 所有数据发送完成
    last_error_ = SocketError::SUCCESS;
            return last_error_;
}

SocketError TcpSocket::sendfile_zero_copy(int file_fd, off_t offset, size_t count, size_t& sent) {
    if (sockfd_ < 0 || !connected_) {
        last_error_ = SocketError::INVALID_STATE;
                return last_error_;
            }
            
    if (file_fd < 0 || count == 0) {
        last_error_ = SocketError::INVALID_ARGUMENT;
        return last_error_;
    }
    
    sent = 0;
    
#ifdef __linux__
    // Linux的sendfile实现
    ssize_t bytes_sent = ::sendfile(sockfd_, file_fd, &offset, count);
    if (bytes_sent < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            last_error_ = SocketError::TIMEOUT;
            return last_error_;
        } else if (errno == EPIPE || errno == ECONNRESET) {
            connected_ = false;
            last_error_ = SocketError::CLOSED;
            return last_error_;
            } else {
            last_error_ = SocketError::SEND_FAILED;
            LOG_ERROR("sendfile failed: %s (errno=%d)", strerror(errno), errno);
            return last_error_;
        }
    }
    
    sent = static_cast<size_t>(bytes_sent);
    last_error_ = SocketError::SUCCESS;
    
    LOG_DEBUG("sendfile sent %zu bytes from offset %ld", sent, offset);
    return last_error_;
    
#else
    // 非Linux系统回退到常规读写
    LOG_WARNING("sendfile not supported on this platform, falling back to regular I/O");
    
    // 分配缓冲区
    const size_t buffer_size = 64 * 1024; // 64KB
    std::vector<uint8_t> buffer(buffer_size);
    
    // 定位文件偏移
    if (lseek(file_fd, offset, SEEK_SET) != offset) {
        last_error_ = SocketError::SEND_FAILED;
        LOG_ERROR("Failed to seek file to offset %ld: %s", offset, strerror(errno));
        return last_error_;
    }
    
    size_t remaining = count;
    while (remaining > 0 && sent < count) {
        size_t to_read = std::min(remaining, buffer_size);
        
        // 读取文件数据
        ssize_t bytes_read = ::read(file_fd, buffer.data(), to_read);
        if (bytes_read <= 0) {
            if (bytes_read < 0) {
                last_error_ = SocketError::SEND_FAILED;
                LOG_ERROR("Failed to read from file: %s", strerror(errno));
            } else {
                // 文件结束
                break;
            }
            return last_error_;
        }
        
        // 发送数据
        SocketError err = send_all(buffer.data(), bytes_read);
        if (err != SocketError::SUCCESS) {
            last_error_ = err;
            return last_error_;
        }
        
        sent += bytes_read;
        remaining -= bytes_read;
    }
    
    last_error_ = SocketError::SUCCESS;
                    return last_error_;
#endif
}

SocketError TcpSocket::send_mmap_zero_copy(void* mmap_addr, size_t len) {
    if (sockfd_ < 0 || !connected_) {
        last_error_ = SocketError::INVALID_STATE;
        return last_error_;
    }
    
    if (!mmap_addr || len == 0) {
        last_error_ = SocketError::INVALID_ARGUMENT;
        return last_error_;
    }
    
    // 使用MSG_MORE标志进行高效传输
    // 这告诉内核我们可能有更多数据要发送，可以进行优化
    const int flags = MSG_NOSIGNAL | MSG_MORE;
    
    size_t total_sent = 0;
    const uint8_t* buffer = static_cast<const uint8_t*>(mmap_addr);
    
    // 优化块大小 - 使用较大的块以减少系统调用
    const size_t chunk_size = 256 * 1024; // 256KB
    
    while (total_sent < len) {
        size_t current_chunk = std::min(chunk_size, len - total_sent);
        bool is_last_chunk = (total_sent + current_chunk >= len);
        
        // 最后一块不使用MSG_MORE标志
        int send_flags = is_last_chunk ? MSG_NOSIGNAL : flags;
        
        ssize_t sent = ::send(sockfd_, buffer + total_sent, current_chunk, send_flags);
        
        if (sent < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                // 缓冲区满，短暂等待
                std::this_thread::sleep_for(std::chrono::milliseconds(10));
                continue;
            } else if (errno == EPIPE || errno == ECONNRESET) {
                connected_ = false;
                last_error_ = SocketError::CLOSED;
                return last_error_;
            } else {
                last_error_ = SocketError::SEND_FAILED;
                LOG_ERROR("send_mmap_zero_copy failed: %s (errno=%d)", strerror(errno), errno);
                return last_error_;
            }
        } else if (sent == 0) {
            // 连接关闭
            connected_ = false;
            last_error_ = SocketError::CLOSED;
            return last_error_;
        }
        
        total_sent += sent;
    }
    
    last_error_ = SocketError::SUCCESS;
    LOG_DEBUG("send_mmap_zero_copy sent %zu bytes", total_sent);
    return last_error_;
}

SocketError TcpSocket::recv_all(void* buffer, size_t len) {
    if (sockfd_ < 0) {
        last_error_ = SocketError::INVALID_STATE;
        return last_error_;
    }
    
    if (!buffer || len == 0) {
        last_error_ = SocketError::INVALID_ARGUMENT;
        return last_error_;
    }
    
    // 使用偏移量跟踪已接收的数据
    size_t total_received = 0;
    uint8_t* buf_ptr = static_cast<uint8_t*>(buffer);
    
    // 记录开始时间用于超时检测
    auto start_time = std::chrono::steady_clock::now();
    
    // 计算总超时时间 (原超时时间的1.5倍，考虑到重试)
    auto total_timeout_ms = options_.recv_timeout.count() * 1.5;
    
    // 最大重试次数和延迟
    const int max_retries = 5;
    int retry_count = 0;
    
    // 优化：使用批量接收，减少系统调用次数
    const size_t optimal_batch_size = 64 * 1024;  // 64KB
    
    while (total_received < len) {
        // 计算当前已用时间
        auto current_time = std::chrono::steady_clock::now();
        auto elapsed_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
            current_time - start_time).count();
        
        // 检查是否超时
        if (elapsed_ms > total_timeout_ms) {
            last_error_ = SocketError::TIMEOUT;
            LOG_ERROR("recv_all timeout after %lld ms", elapsed_ms);
            return last_error_;
        }
        
        // 检查socket是否有效
        if (sockfd_ < 0 || !connected_) {
            last_error_ = SocketError::INVALID_STATE;
            return last_error_;
        }
        
        // 计算当前批次大小
        size_t batch_size = len - total_received;
        if (batch_size > optimal_batch_size) {
            batch_size = optimal_batch_size;
        }
        
        // 尝试接收数据
        ssize_t received = ::recv(sockfd_, buf_ptr + total_received, batch_size, 0);
        
        if (received < 0) {
            if (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK) {
                retry_count++;
                if (retry_count > max_retries) {
                    last_error_ = SocketError::TIMEOUT;
                    return last_error_;
                }
                // 短暂休眠后继续，使用指数退避策略
                std::this_thread::sleep_for(std::chrono::milliseconds(50 * (1 << retry_count)));
                continue;
            } else if (errno == ECONNRESET || errno == ECONNABORTED) {
                // 连接被对端重置
                last_error_ = SocketError::CLOSED;
                connected_ = false;
                LOG_ERROR("recv_all: connection reset by peer: %s (errno=%d)", strerror(errno), errno);
                return last_error_;
            } else {
                // 其他错误视为严重错误
                last_error_ = SocketError::RECV_FAILED;
                LOG_ERROR("recv_all: recv failed: %s (errno=%d)", strerror(errno), errno);
                return last_error_;
            }
        } else if (received == 0) {
            // 接收0字节表示对方已关闭连接
            last_error_ = SocketError::CLOSED;
            connected_ = false;
            return last_error_;
        }
        
        // 更新已接收字节数
        total_received += received;
        
        // 成功接收数据后重置重试计数
        retry_count = 0;
    }
    
    // 所有数据接收完成
    last_error_ = SocketError::SUCCESS;
    return last_error_;
}

void TcpSocket::close() {
    if (sockfd_ >= 0) {
        // 首先尝试正常关闭套接字
        ::shutdown(sockfd_, SHUT_RDWR);
        
        // 再关闭文件描述符
        ::close(sockfd_);
        sockfd_ = -1;
    }
    connected_ = false;
    
    // 清除地址信息
    local_ip_ = "";
    local_port_ = 0;
    remote_ip_ = "";
    remote_port_ = 0;
}

bool TcpSocket::set_non_blocking(bool non_blocking) {
    if (sockfd_ < 0) {
        return false;
    }
    
    int flags = fcntl(sockfd_, F_GETFL, 0);
    if (flags < 0) {
        return false;
    }
    
    if (non_blocking) {
        flags |= O_NONBLOCK;
    } else {
        flags &= ~O_NONBLOCK;
    }
    
    if (fcntl(sockfd_, F_SETFL, flags) < 0) {
        return false;
    }
    
    options_.non_blocking = non_blocking;
    return true;
}

void TcpSocket::apply_socket_options() {
    if (sockfd_ < 0) {
        return;
    }
    
    // 设置地址重用
    if (options_.reuse_address) {
        int opt = 1;
        if (setsockopt(sockfd_, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0) {
            LOG_WARNING("Failed to set SO_REUSEADDR: %s (errno=%d)", strerror(errno), errno);
        }
    }
    
    // 设置端口重用
    if (options_.reuse_port) {
        #ifdef SO_REUSEPORT
        int opt = 1;
        if (setsockopt(sockfd_, SOL_SOCKET, SO_REUSEPORT, &opt, sizeof(opt)) < 0) {
            LOG_WARNING("Failed to set SO_REUSEPORT: %s (errno=%d)", strerror(errno), errno);
        }
        #endif
    }
    
    // 设置保活
    if (options_.keep_alive) {
        int opt = 1;
        if (setsockopt(sockfd_, SOL_SOCKET, SO_KEEPALIVE, &opt, sizeof(opt)) < 0) {
            LOG_WARNING("Failed to set SO_KEEPALIVE: %s (errno=%d)", strerror(errno), errno);
        }
        
        // 设置TCP保活参数
        #ifdef TCP_KEEPIDLE
        if (setsockopt(sockfd_, IPPROTO_TCP, TCP_KEEPIDLE, &options_.keep_idle, sizeof(options_.keep_idle)) < 0) {
            LOG_WARNING("Failed to set TCP_KEEPIDLE: %s (errno=%d)", strerror(errno), errno);
        }
        #endif
        
        #ifdef TCP_KEEPINTVL
        if (setsockopt(sockfd_, IPPROTO_TCP, TCP_KEEPINTVL, &options_.keep_interval, sizeof(options_.keep_interval)) < 0) {
            LOG_WARNING("Failed to set TCP_KEEPINTVL: %s (errno=%d)", strerror(errno), errno);
        }
        #endif
        
        #ifdef TCP_KEEPCNT
        if (setsockopt(sockfd_, IPPROTO_TCP, TCP_KEEPCNT, &options_.keep_count, sizeof(options_.keep_count)) < 0) {
            LOG_WARNING("Failed to set TCP_KEEPCNT: %s (errno=%d)", strerror(errno), errno);
        }
        #endif
    }
    
    // 禁用Nagle算法，减少小包延迟
    int flag = 1;
    if (setsockopt(sockfd_, IPPROTO_TCP, TCP_NODELAY, &flag, sizeof(flag)) < 0) {
        LOG_WARNING("Failed to set TCP_NODELAY: %s (errno=%d)", strerror(errno), errno);
    }
    
    // 设置发送缓冲区大小
    if (options_.send_buffer_size > 0) {
        if (setsockopt(sockfd_, SOL_SOCKET, SO_SNDBUF, &options_.send_buffer_size, sizeof(options_.send_buffer_size)) < 0) {
            LOG_WARNING("Failed to set send buffer size to %d: %s (errno=%d)", 
                      options_.send_buffer_size, strerror(errno), errno);
        }
    }
    
    // 设置接收缓冲区大小
    if (options_.recv_buffer_size > 0) {
        if (setsockopt(sockfd_, SOL_SOCKET, SO_RCVBUF, &options_.recv_buffer_size, sizeof(options_.recv_buffer_size)) < 0) {
            LOG_WARNING("Failed to set receive buffer size to %d: %s (errno=%d)", 
                      options_.recv_buffer_size, strerror(errno), errno);
        }
    }
    
    // 设置非阻塞模式
    if (options_.non_blocking) {
        set_non_blocking(true);
    }
    
    // 设置超时选项
    if (options_.recv_timeout.count() > 0) {
        struct timeval tv;
        tv.tv_sec = options_.recv_timeout.count() / 1000;
        tv.tv_usec = (options_.recv_timeout.count() % 1000) * 1000;
        if (setsockopt(sockfd_, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) < 0) {
            LOG_WARNING("Failed to set receive timeout: %s (errno=%d)", strerror(errno), errno);
        }
    }
    
    if (options_.send_timeout.count() > 0) {
        struct timeval tv;
        tv.tv_sec = options_.send_timeout.count() / 1000;
        tv.tv_usec = (options_.send_timeout.count() % 1000) * 1000;
        if (setsockopt(sockfd_, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv)) < 0) {
            LOG_WARNING("Failed to set send timeout: %s (errno=%d)", strerror(errno), errno);
        }
    }
}

void TcpSocket::set_recv_timeout(std::chrono::milliseconds timeout) {
    options_.recv_timeout = timeout;
    
    if (sockfd_ >= 0) {
        struct timeval tv;
        tv.tv_sec = timeout.count() / 1000;
        tv.tv_usec = (timeout.count() % 1000) * 1000;
        if (setsockopt(sockfd_, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) < 0) {
            LOG_WARNING("Failed to set receive timeout: %s (errno=%d)", strerror(errno), errno);
        }
    }
}

void TcpSocket::update_local_address() {
    if (sockfd_ < 0) {
        return;
    }
    
    struct sockaddr_in addr;
    socklen_t addr_len = sizeof(addr);
    if (getsockname(sockfd_, (struct sockaddr*)&addr, &addr_len) == 0) {
        char ip_buf[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &addr.sin_addr, ip_buf, sizeof(ip_buf));
        local_ip_ = ip_buf;
        local_port_ = ntohs(addr.sin_port);
    }
}

void TcpSocket::update_remote_address() {
    if (sockfd_ < 0) {
        return;
    }
    
    struct sockaddr_in addr;
    socklen_t addr_len = sizeof(addr);
    if (getpeername(sockfd_, (struct sockaddr*)&addr, &addr_len) == 0) {
        char ip_buf[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &addr.sin_addr, ip_buf, sizeof(ip_buf));
        remote_ip_ = ip_buf;
        remote_port_ = ntohs(addr.sin_port);
    }
}

bool TcpSocket::is_connected() const {
    // 基本检查
    if (sockfd_ < 0 || !connected_) {
        return false;
    }
    
    // 主动检测连接状态
    struct pollfd pfd;
    pfd.fd = sockfd_;
    pfd.events = POLLIN | POLLOUT;  // 检查读写状态
    pfd.revents = 0;
    
    // 非阻塞式轮询，立即返回
    int ret = poll(&pfd, 1, 0);
    
    // poll错误
    if (ret < 0) {
        // 忽略EINTR错误，这只是被信号中断
        if (errno == EINTR) {
            return true;  // 被信号中断不代表连接断开
        }
        return false;
    }
    
    // 检查是否有错误或挂断情况
    if (pfd.revents & (POLLERR | POLLHUP | POLLNVAL)) {
        return false;
    }
    
    // 连接正常
    return true;
}

} // namespace network
} // namespace ft 
