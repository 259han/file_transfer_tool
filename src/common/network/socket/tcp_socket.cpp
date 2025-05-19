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
#include "../../utils/logging/logger.h"

namespace ft {
namespace network {

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

TcpSocket::TcpSocket(int sockfd, const SocketOptions& options)
    : sockfd_(sockfd),
      options_(options),
      connected_(sockfd >= 0),
      local_ip_(""),
      local_port_(0),
      remote_ip_(""),
      remote_port_(0),
      last_error_(SocketError::SUCCESS) {
    
    if (sockfd_ >= 0) {
        // 应用套接字选项
        apply_socket_options();
        
        // 获取本地地址信息
        struct sockaddr_in addr;
        socklen_t addr_len = sizeof(addr);
        if (getsockname(sockfd_, (struct sockaddr*)&addr, &addr_len) == 0) {
            get_socket_address(addr, local_ip_, local_port_);
        }
        
        // 获取远程地址信息
        if (getpeername(sockfd_, (struct sockaddr*)&addr, &addr_len) == 0) {
            get_socket_address(addr, remote_ip_, remote_port_);
        }
    }
}

TcpSocket::TcpSocket(const TcpSocket& other)
    : sockfd_(-1),
      options_(other.options_),
      connected_(false),
      local_ip_(other.local_ip_),
      local_port_(other.local_port_),
      remote_ip_(other.remote_ip_),
      remote_port_(other.remote_port_) {
    
    // 如果原socket有效，创建一个新的socket
    if (other.sockfd_ >= 0 && other.connected_) {
        // 创建新的套接字
        sockfd_ = socket(AF_INET, SOCK_STREAM, 0);
        if (sockfd_ < 0) {
            LOG_ERROR("Failed to create socket in copy constructor: %s (errno=%d)", 
                    strerror(errno), errno);
            return;
        }
        
        // 应用套接字选项
        apply_socket_options();
        
        // 注意：复制构造函数不会复制连接状态，因为我们无法复制底层连接
        // 这里不会自动连接到相同的远程主机，需要调用者手动重新连接
        LOG_WARNING("Socket copied but not connected. Call connect() to establish connection.");
    }
}

TcpSocket& TcpSocket::operator=(const TcpSocket& other) {
    if (this != &other) {
        // 关闭现有套接字
        if (sockfd_ >= 0) {
            ::close(sockfd_);
            sockfd_ = -1;
        }
        
        // 复制基本属性
        options_ = other.options_;
        connected_ = false;  // 默认为未连接
        local_ip_ = other.local_ip_;
        local_port_ = other.local_port_;
        remote_ip_ = other.remote_ip_;
        remote_port_ = other.remote_port_;
        
        // 如果原socket有效，创建一个新的socket
        if (other.sockfd_ >= 0 && other.connected_) {
            // 创建新的套接字
            sockfd_ = socket(AF_INET, SOCK_STREAM, 0);
            if (sockfd_ < 0) {
                LOG_ERROR("Failed to create socket in assignment operator: %s (errno=%d)", 
                        strerror(errno), errno);
                return *this;
            }
            
            // 应用套接字选项
            apply_socket_options();
            
            // 注意：赋值操作不会复制连接状态
            LOG_WARNING("Socket assigned but not connected. Call connect() to establish connection.");
        }
    }
    return *this;
}

TcpSocket::TcpSocket(TcpSocket&& other) noexcept
    : sockfd_(other.sockfd_),
      options_(std::move(other.options_)),
      connected_(other.connected_),
      local_ip_(std::move(other.local_ip_)),
      local_port_(other.local_port_),
      remote_ip_(std::move(other.remote_ip_)),
      remote_port_(other.remote_port_) {
    
    // 添加详细的移动构造函数日志
    LOG_DEBUG("TcpSocket move constructor: Moving fd=%d, connected=%d, remote=%s:%d", 
            sockfd_, connected_ ? 1 : 0, remote_ip_.c_str(), remote_port_);
    
    // 防止源对象析构时关闭socket
    int old_fd = other.sockfd_;
    other.sockfd_ = -1;
    other.connected_ = false;
    other.local_port_ = 0;
    other.remote_port_ = 0;
    
    LOG_DEBUG("TcpSocket move constructor: Source fd changed from %d to %d", old_fd, other.sockfd_);
}

TcpSocket& TcpSocket::operator=(TcpSocket&& other) noexcept {
    if (this != &other) {
        // 关闭现有套接字
        int old_fd = sockfd_;
        if (sockfd_ >= 0) {
            LOG_DEBUG("TcpSocket move assignment: Closing existing socket fd=%d", sockfd_);
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
        
        // 添加详细的移动赋值运算符日志
        LOG_DEBUG("TcpSocket move assignment: Changed fd from %d to %d, connected=%d, remote=%s:%d", 
                old_fd, sockfd_, connected_ ? 1 : 0, remote_ip_.c_str(), remote_port_);
        
        // 防止源对象析构时关闭socket
        int old_other_fd = other.sockfd_;
        other.sockfd_ = -1;
        other.connected_ = false;
        other.local_port_ = 0;
        other.remote_port_ = 0;
        
        LOG_DEBUG("TcpSocket move assignment: Source fd changed from %d to %d", old_other_fd, other.sockfd_);
    }
    return *this;
}

TcpSocket::~TcpSocket() {
    close();
}

SocketError TcpSocket::bind(const std::string& host, uint16_t port) {
    if (sockfd_ < 0) {
        return SocketError::INVALID_STATE;
    }
    
    struct sockaddr_in addr;
    std::memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    
    if (host.empty() || host == "0.0.0.0") {
        addr.sin_addr.s_addr = htonl(INADDR_ANY);
    } else {
        if (inet_pton(AF_INET, host.c_str(), &addr.sin_addr) <= 0) {
            return SocketError::INVALID_ARGUMENT;
        }
    }
    
    if (::bind(sockfd_, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        return SocketError::BIND_FAILED;
    }
    
    // 保存本地地址信息
    local_ip_ = host;
    local_port_ = port;
    
    return SocketError::SUCCESS;
}

SocketError TcpSocket::listen(int backlog) {
    if (sockfd_ < 0) {
        return SocketError::INVALID_STATE;
    }
    
    if (::listen(sockfd_, backlog) < 0) {
        return SocketError::LISTEN_FAILED;
    }
    
    return SocketError::SUCCESS;
}

SocketError TcpSocket::accept(TcpSocket& client_socket) {
    if (sockfd_ < 0) {
        return SocketError::INVALID_STATE;
    }
    
    struct sockaddr_in addr;
    socklen_t addr_len = sizeof(addr);
    LOG_INFO("Accepting connections on %s:%d (fd=%d)", local_ip_.c_str(), local_port_, sockfd_);
            
    int client_fd = ::accept(sockfd_, (struct sockaddr*)&addr, &addr_len);
    if (client_fd < 0) {
        LOG_ERROR("Accept failed: %s (errno=%d)", strerror(errno), errno);
        return SocketError::ACCEPT_FAILED;
    }
    
    LOG_INFO("Accepted connection, new socket fd=%d", client_fd);
    
    // 设置TCP选项，确保客户端连接的可靠性
    
    // 禁用Nagle算法
    int flag = 1;
    if (setsockopt(client_fd, IPPROTO_TCP, TCP_NODELAY, &flag, sizeof(flag)) < 0) {
        LOG_WARNING("Warning: Failed to set TCP_NODELAY on client socket: %s (errno=%d)", strerror(errno), errno);
        // 继续执行，这不是致命错误
    }
    
    // 设置TCP保活选项，更早检测断开的连接
    int keepalive = 1;
    int keepidle = 10;   // 10秒无数据传输就开始发送保活包
    int keepintvl = 1;   // 每1秒发送一次保活包
    int keepcnt = 3;     // 最多发送3次保活包
    
    // 启用保活
    if (setsockopt(client_fd, SOL_SOCKET, SO_KEEPALIVE, &keepalive, sizeof(keepalive)) < 0) {
        LOG_WARNING("Warning: Failed to set SO_KEEPALIVE on client socket: %s (errno=%d)", strerror(errno), errno);
    }
    
    // 设置保活参数 (仅适用于Linux系统)
#ifdef TCP_KEEPIDLE
    if (setsockopt(client_fd, IPPROTO_TCP, TCP_KEEPIDLE, &keepidle, sizeof(keepidle)) < 0) {
        LOG_WARNING("Warning: Failed to set TCP_KEEPIDLE on client socket: %s (errno=%d)", strerror(errno), errno);
    }
#endif

#ifdef TCP_KEEPINTVL
    if (setsockopt(client_fd, IPPROTO_TCP, TCP_KEEPINTVL, &keepintvl, sizeof(keepintvl)) < 0) {
        LOG_WARNING("Warning: Failed to set TCP_KEEPINTVL on client socket: %s (errno=%d)", strerror(errno), errno);
    }
#endif

#ifdef TCP_KEEPCNT
    if (setsockopt(client_fd, IPPROTO_TCP, TCP_KEEPCNT, &keepcnt, sizeof(keepcnt)) < 0) {
        LOG_WARNING("Warning: Failed to set TCP_KEEPCNT on client socket: %s (errno=%d)", strerror(errno), errno);
    }
#endif
    
    // 获取客户端地址信息
    std::string client_ip;
    uint16_t client_port;
    get_socket_address(addr, client_ip, client_port);
    
    LOG_INFO("Client connection details - address=%s:%d", client_ip.c_str(), client_port);
    
    // 关闭客户端套接字现有的fd，防止资源泄漏
    LOG_INFO("Closing client_socket existing fd=%d before assigning new fd=%d", client_socket.sockfd_, client_fd);
    client_socket.close();
    
    // 记录当前客户端socket状态
    LOG_INFO("Before assignment - client_socket: fd=%d, connected=%d, remote=%s:%d", client_socket.sockfd_, client_socket.connected_ ? 1 : 0, client_socket.remote_ip_.c_str(), client_socket.remote_port_);
    
    // 使用移动构造创建新的TcpSocket临时对象，然后赋值给客户端套接字
    // 这样可以确保所有状态被正确初始化
    TcpSocket temp_socket(client_fd, options_);
    
    // 手动设置temp_socket的连接状态和地址信息
    temp_socket.connected_ = true;
    temp_socket.remote_ip_ = client_ip;
    temp_socket.remote_port_ = client_port;
    temp_socket.local_ip_ = local_ip_;
    temp_socket.local_port_ = local_port_;
    
    // 使用移动赋值将临时对象赋值给client_socket
    client_socket = std::move(temp_socket);
    
    // 验证客户端套接字状态
    LOG_INFO("After assignment - client_socket: fd=%d, connected=%d, remote=%s:%d", client_socket.sockfd_, client_socket.connected_ ? 1 : 0, client_socket.remote_ip_.c_str(), client_socket.remote_port_);
    
    // 验证客户端套接字是否仍然连接
    if (!client_socket.is_connected()) {
        LOG_WARNING("Warning: Client socket not connected after accept and assignment");
    } else {
        LOG_INFO("Client socket successfully connected and assigned");
    }
    
    LOG_INFO("Accepted connection from %s:%d on socket fd=%d", client_ip.c_str(), client_port, client_socket.sockfd_);
    
    return SocketError::SUCCESS;
}

SocketError TcpSocket::connect(const std::string& host, uint16_t port) {
    if (sockfd_ < 0) {
        last_error_ = SocketError::INVALID_STATE;
        LOG_ERROR("connect: Invalid socket state");
        return last_error_;
    }
    
    // 如果已经连接，先关闭现有连接
    if (connected_) {
        close();
        
        // 重新创建socket
        sockfd_ = socket(AF_INET, SOCK_STREAM, 0);
        if (sockfd_ < 0) {
            last_error_ = SocketError::SOCKET_CREATE_FAILED;
            LOG_ERROR("connect: Failed to create new socket: %s (errno=%d)",
                   strerror(errno), errno);
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
            LOG_ERROR("connect: Failed to resolve hostname %s: %s (h_errno=%d)",
                   host.c_str(), hstrerror(h_errno), h_errno);
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
        
        // 恢复为阻塞模式
        fcntl(sockfd_, F_SETFL, flags);
        
        if (ret < 0) {
            // poll系统调用出错
            last_error_ = SocketError::CONNECT_FAILED;
            LOG_ERROR("connect: poll error during connect: %s (errno=%d)",
                   strerror(errno), errno);
            return last_error_;
        } else if (ret == 0) {
            // 连接超时
            last_error_ = SocketError::TIMEOUT;
            LOG_ERROR("connect: Timeout connecting to %s:%d", host.c_str(), port);
            return last_error_;
        } else {
            // 检查socket是否有错误
            if (pfd.revents & (POLLERR | POLLHUP | POLLNVAL)) {
                // 获取具体错误
                int err;
                socklen_t err_len = sizeof(err);
                getsockopt(sockfd_, SOL_SOCKET, SO_ERROR, &err, &err_len);
                
                last_error_ = SocketError::CONNECT_FAILED;
                LOG_ERROR("connect: Failed to connect to %s:%d: %s (errno=%d)",
                       host.c_str(), port, strerror(err), err);
                return last_error_;
            }
            
            // 连接成功
            connected_ = true;
            remote_ip_ = host;
            remote_port_ = port;
            
            // 获取本地地址
            struct sockaddr_in local_addr;
            socklen_t addr_len = sizeof(local_addr);
            if (getsockname(sockfd_, (struct sockaddr*)&local_addr, &addr_len) == 0) {
                char ip_buf[INET_ADDRSTRLEN];
                inet_ntop(AF_INET, &local_addr.sin_addr, ip_buf, sizeof(ip_buf));
                local_ip_ = ip_buf;
                local_port_ = ntohs(local_addr.sin_port);
            }
            
            LOG_INFO("Connected to %s:%d from local %s:%d", 
                     host.c_str(), port, local_ip_.c_str(), local_port_);
            
            last_error_ = SocketError::SUCCESS;
            return last_error_;
        }
    } else {
        // 恢复为阻塞模式
        fcntl(sockfd_, F_SETFL, flags);
        
        last_error_ = SocketError::CONNECT_FAILED;
        LOG_ERROR("connect: Failed to connect to %s:%d: %s (errno=%d)",
               host.c_str(), port, strerror(errno), errno);
        return last_error_;
    }
}

SocketError TcpSocket::send(const void* data, size_t len, size_t& sent_len) {
    if (sockfd_ < 0) {
        last_error_ = SocketError::INVALID_STATE;
        return SocketError::INVALID_STATE;
    }
    
    if (!data || len == 0) {
        last_error_ = SocketError::INVALID_ARGUMENT;
        return SocketError::INVALID_ARGUMENT;
    }
    
    // 检查连接状态
    if (!connected_) {
        last_error_ = SocketError::CLOSED;
        return SocketError::CLOSED;
    }
    
    // 非阻塞发送，支持超时
    if (options_.non_blocking || options_.send_timeout.count() > 0) {
        struct pollfd pfd;
        pfd.fd = sockfd_;
        pfd.events = POLLOUT;
        
        int poll_ret = poll(&pfd, 1, options_.send_timeout.count());
        if (poll_ret == 0) {
            // 发送超时
            last_error_ = SocketError::TIMEOUT;
            return SocketError::TIMEOUT;
        } else if (poll_ret < 0) {
            // Poll错误
            last_error_ = SocketError::SEND_FAILED;
            return SocketError::SEND_FAILED;
        }
        
        // 检查套接字是否可写
        if (!(pfd.revents & POLLOUT)) {
            if (pfd.revents & (POLLERR | POLLHUP | POLLNVAL)) {
                // 连接关闭或错误
                connected_ = false;
                last_error_ = SocketError::CLOSED;
                return SocketError::CLOSED;
            }
            // 其他错误
            last_error_ = SocketError::SEND_FAILED;
            return SocketError::SEND_FAILED;
        }
    }
    
    // 尝试发送数据
    ssize_t ret = ::send(sockfd_, data, len, 0);
    if (ret < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            // 资源暂时不可用，可以重试
            sent_len = 0;
            last_error_ = SocketError::TIMEOUT;
            return SocketError::TIMEOUT;
        } else if (errno == EPIPE || errno == ECONNRESET) {
            // 连接已关闭
            connected_ = false;
            last_error_ = SocketError::CLOSED;
            return SocketError::CLOSED;
        } else {
            // 其他发送错误
            last_error_ = SocketError::SEND_FAILED;
            return SocketError::SEND_FAILED;
        }
    }
    
    // 成功发送
    sent_len = static_cast<size_t>(ret);
    last_error_ = SocketError::SUCCESS;
    return SocketError::SUCCESS;
}

SocketError TcpSocket::recv(void* buffer, size_t len, size_t& received_len) {
    if (sockfd_ < 0) {
        last_error_ = SocketError::INVALID_STATE;
        return SocketError::INVALID_STATE;
    }
    
    if (!buffer || len == 0) {
        last_error_ = SocketError::INVALID_ARGUMENT;
        return SocketError::INVALID_ARGUMENT;
    }
    
    // 检查连接状态
    if (!connected_) {
        last_error_ = SocketError::CLOSED;
        return SocketError::CLOSED;
    }
    
    // 非阻塞接收，支持超时
    if (options_.non_blocking || options_.recv_timeout.count() > 0) {
        struct pollfd pfd;
        pfd.fd = sockfd_;
        pfd.events = POLLIN;
        
        int poll_ret = poll(&pfd, 1, options_.recv_timeout.count());
        if (poll_ret == 0) {
            // 接收超时
            received_len = 0;
            last_error_ = SocketError::TIMEOUT;
            return SocketError::TIMEOUT;
        } else if (poll_ret < 0) {
            // Poll错误
            last_error_ = SocketError::RECV_FAILED;
            return SocketError::RECV_FAILED;
        }
        
        // 检查套接字是否可读
        if (!(pfd.revents & POLLIN)) {
            if (pfd.revents & (POLLERR | POLLHUP | POLLNVAL)) {
                // 连接关闭或错误
                connected_ = false;
                last_error_ = SocketError::CLOSED;
                return SocketError::CLOSED;
            }
            // 其他错误
            last_error_ = SocketError::RECV_FAILED;
            return SocketError::RECV_FAILED;
        }
    }
    
    // 尝试接收数据
    ssize_t ret = ::recv(sockfd_, buffer, len, 0);
    if (ret < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            // 资源暂时不可用，可以重试
            received_len = 0;
            last_error_ = SocketError::TIMEOUT;
            return SocketError::TIMEOUT;
        } else if (errno == ECONNRESET) {
            // 连接已重置
            connected_ = false;
            last_error_ = SocketError::CLOSED;
            return SocketError::CLOSED;
        } else {
            // 其他接收错误
            last_error_ = SocketError::RECV_FAILED;
            return SocketError::RECV_FAILED;
        }
    } else if (ret == 0) {
        // 对端关闭连接
        connected_ = false;
        last_error_ = SocketError::CLOSED;
        return SocketError::CLOSED;
    }
    
    // 成功接收
    received_len = static_cast<size_t>(ret);
    last_error_ = SocketError::SUCCESS;
    return SocketError::SUCCESS;
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
    auto current_time = start_time;
    
    // 计算总超时时间 (原超时时间的1.5倍，考虑到重试)
    auto total_timeout_ms = options_.send_timeout.count() * 1.5;
    
    // 最大重试次数和延迟
    const int max_retries = 3;
    int retry_count = 0;
    
    while (total_sent < len) {
        // 计算当前已用时间
        current_time = std::chrono::steady_clock::now();
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
            LOG_ERROR("send_all: socket not connected");
            return last_error_;
        }
        
        // 检查socket是否可写
        struct pollfd pfd;
        pfd.fd = sockfd_;
        pfd.events = POLLOUT;
        pfd.revents = 0;
        
        // 计算剩余超时时间
        int remaining_timeout_ms = static_cast<int>(total_timeout_ms - elapsed_ms);
        if (remaining_timeout_ms < 0) remaining_timeout_ms = 0;
        
        int poll_result = poll(&pfd, 1, remaining_timeout_ms);
        
        if (poll_result < 0) {
            // 系统调用被中断，这是可以恢复的，直接继续
            if (errno == EINTR) {
                continue;
            }
            
            // 其他不可恢复错误
            last_error_ = SocketError::SEND_FAILED;
            LOG_ERROR("send_all: poll failed: %s (errno=%d)", strerror(errno), errno);
            return last_error_;
        } else if (poll_result == 0) {
            // poll超时，但总时间可能还没到
            retry_count++;
            
            if (retry_count > max_retries) {
                last_error_ = SocketError::TIMEOUT;
                LOG_ERROR("send_all: poll timeout after %d retries", max_retries);
                return last_error_;
            }
            
            // 短暂休眠后继续
            std::this_thread::sleep_for(std::chrono::milliseconds(50));
            continue;
        }
        
        // 检查socket错误
        if (pfd.revents & (POLLERR | POLLHUP | POLLNVAL)) {
            last_error_ = SocketError::CLOSED;
            connected_ = false;
            LOG_ERROR("send_all: socket error: %s (revents=0x%x)", strerror(errno), pfd.revents);
            return last_error_;
        }
        
        // 尝试发送数据
        ssize_t sent = ::send(sockfd_, buffer + total_sent, len - total_sent, MSG_NOSIGNAL);
        
        if (sent < 0) {
            // 处理特定错误
            if (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK) {
                // 这些错误是可恢复的，我们继续尝试
                retry_count++;
                
                if (retry_count > max_retries) {
                    last_error_ = SocketError::TIMEOUT;
                    LOG_ERROR("send_all: too many retries on EAGAIN/EWOULDBLOCK");
                    return last_error_;
                }
                
                // 短暂休眠后继续
                std::this_thread::sleep_for(std::chrono::milliseconds(50));
                continue;
            } else if (errno == EPIPE || errno == ECONNRESET) {
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
            LOG_ERROR("send_all: connection closed (sent 0 bytes)");
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
    auto current_time = start_time;
    
    // 计算总超时时间 (原超时时间的1.5倍，考虑到重试)
    auto total_timeout_ms = options_.recv_timeout.count() * 1.5;
    
    // 最大重试次数和延迟
    const int max_retries = 3;
    int retry_count = 0;
    
    while (total_received < len) {
        // 计算当前已用时间
        current_time = std::chrono::steady_clock::now();
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
            LOG_ERROR("recv_all: socket not connected");
            return last_error_;
        }
        
        // 检查socket是否可读
        struct pollfd pfd;
        pfd.fd = sockfd_;
        pfd.events = POLLIN;
        pfd.revents = 0;
        
        // 计算剩余超时时间
        int remaining_timeout_ms = static_cast<int>(total_timeout_ms - elapsed_ms);
        if (remaining_timeout_ms < 0) remaining_timeout_ms = 0;
        
        int poll_result = poll(&pfd, 1, remaining_timeout_ms);
        
        if (poll_result < 0) {
            // 系统调用被中断，这是可以恢复的，直接继续
            if (errno == EINTR) {
                continue;
            }
            
            // 其他不可恢复错误
            last_error_ = SocketError::RECV_FAILED;
            LOG_ERROR("recv_all: poll failed: %s (errno=%d)", strerror(errno), errno);
            return last_error_;
        } else if (poll_result == 0) {
            // poll超时，但总时间可能还没到
            retry_count++;
            
            if (retry_count > max_retries) {
                last_error_ = SocketError::TIMEOUT;
                LOG_ERROR("recv_all: poll timeout after %d retries", max_retries);
                return last_error_;
            }
            
            // 短暂休眠后继续
            std::this_thread::sleep_for(std::chrono::milliseconds(50));
            continue;
        }
        
        // 检查socket错误
        if (pfd.revents & (POLLERR | POLLHUP | POLLNVAL)) {
            last_error_ = SocketError::CLOSED;
            connected_ = false;
            LOG_ERROR("recv_all: socket error: %s (revents=0x%x)", strerror(errno), pfd.revents);
            return last_error_;
        }
        
        // 尝试接收数据
        ssize_t received = ::recv(sockfd_, buf_ptr + total_received, len - total_received, 0);
        
        if (received < 0) {
            // 处理特定错误
            if (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK) {
                // 这些错误是可恢复的，我们继续尝试
                retry_count++;
                
                if (retry_count > max_retries) {
                    last_error_ = SocketError::TIMEOUT;
                    LOG_ERROR("recv_all: too many retries on EAGAIN/EWOULDBLOCK");
                    return last_error_;
                }
                
                // 短暂休眠后继续
                std::this_thread::sleep_for(std::chrono::milliseconds(50));
                continue;
            } else if (errno == ECONNRESET) {
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
            LOG_INFO("recv_all: connection closed by peer");
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

int TcpSocket::get_fd() const {
    return sockfd_;
}

std::string TcpSocket::get_local_address() const {
    return local_ip_;
}

uint16_t TcpSocket::get_local_port() const {
    return local_port_;
}

std::string TcpSocket::get_remote_address() const {
    return remote_ip_;
}

uint16_t TcpSocket::get_remote_port() const {
    return remote_port_;
}

// 添加一个内部的、非const的检查方法，允许更新connected_状态
bool TcpSocket::check_connection_state_() {
    // 基本检查
    if (sockfd_ < 0 || !connected_) {
        LOG_ERROR("Basic connection check failed: sockfd_=%d, connected_=%d", sockfd_, connected_);
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
        
        // 其他错误表明socket可能有问题
        if (errno != EAGAIN && errno != EWOULDBLOCK) {
            LOG_ERROR("Poll failed in check_connection_state: %s (errno=%d)", 
                    strerror(errno), errno);
        }
        connected_ = false;
        return false;
    }
    
    // 检查是否有错误或挂断情况
    if (pfd.revents & (POLLERR | POLLHUP | POLLNVAL)) {
        // 对于错误状态，获取具体的socket错误
        if (pfd.revents & POLLERR) {
            int error = 0;
            socklen_t len = sizeof(error);
            if (getsockopt(sockfd_, SOL_SOCKET, SO_ERROR, &error, &len) == 0) {
                if (error != 0 && error != EAGAIN && error != EWOULDBLOCK) {
                    LOG_ERROR("Socket error detected in check_connection_state: %s (errno=%d)", 
                            strerror(error), error);
                }
            }
        }
        
        // 更新连接状态
        connected_ = false;
        return false;
    }
    
    // 如果socket可读可写，或者至少其中之一，认为连接正常
    if ((pfd.revents & POLLIN) || (pfd.revents & POLLOUT)) {
        return true;
    }
    
    // 如果poll返回>0但既不可读也不可写，可能有问题
    if (ret > 0) {
        LOG_ERROR("Socket not readable/writable but no error: revents=%d", pfd.revents);
        connected_ = false;
        return false;
    }
    
    // poll返回0，没有事件，但也没有错误，认为连接仍然有效
    return true;
}

bool TcpSocket::is_connected() const {
    // 复制成员变量到本地变量，避免packed结构体问题
    int fd = sockfd_;
    bool connected = connected_;
    
    // 基本检查
    if (fd < 0 || !connected) {
        return false;
    }
    
    // 主动检测连接状态
    struct pollfd pfd;
    pfd.fd = fd;
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
        
        // 其他错误表明socket可能有问题
        if (errno != EAGAIN && errno != EWOULDBLOCK) {
            LOG_ERROR("Poll failed in is_connected: %s (errno=%d)", 
                    strerror(errno), errno);
        }
        return false;
    }
    
    // 检查是否有错误或挂断情况
    if (pfd.revents & (POLLERR | POLLHUP | POLLNVAL)) {
        // 对于错误状态，获取具体的socket错误
        if (pfd.revents & POLLERR) {
            int error = 0;
            socklen_t len = sizeof(error);
            if (getsockopt(fd, SOL_SOCKET, SO_ERROR, &error, &len) == 0) {
                if (error != 0 && error != EAGAIN && error != EWOULDBLOCK) {
                    LOG_ERROR("Socket error detected in is_connected: %s (errno=%d)", 
                            strerror(error), error);
                }
            }
        }
        
        // POLLHUP意味着连接已关闭
        if (pfd.revents & POLLHUP) {
            LOG_WARNING("POLLHUP detected in is_connected (fd=%d)", fd);
            return false;
        }
        
        // POLLNVAL意味着socket描述符无效
        if (pfd.revents & POLLNVAL) {
            LOG_WARNING("POLLNVAL detected in is_connected (fd=%d)", fd);
            return false;
        }
        
        // 在const方法中不能修改connected_成员变量
        return false;
    }
    
    // 如果socket可读可写，或者至少其中之一，认为连接正常
    if ((pfd.revents & POLLIN) || (pfd.revents & POLLOUT)) {
        return true;
    }
    
    // 如果poll返回>0但既不可读也不可写，可能有问题
    if (ret > 0) {
        LOG_ERROR("Socket not readable/writable but no error: revents=%d", pfd.revents);
        return false;
    }
    
    // poll返回0，没有事件，但也没有错误，认为连接仍然有效
    return true;
}

void TcpSocket::set_non_blocking(bool non_blocking) {
    if (sockfd_ < 0) {
        return;
    }
    
    int flags = fcntl(sockfd_, F_GETFL, 0);
    if (flags < 0) {
        return;
    }
    
    if (non_blocking) {
        flags |= O_NONBLOCK;
    } else {
        flags &= ~O_NONBLOCK;
    }
    
    fcntl(sockfd_, F_SETFL, flags);
    options_.non_blocking = non_blocking;
}

void TcpSocket::set_recv_timeout(const std::chrono::milliseconds& timeout) {
    if (sockfd_ < 0) {
        return;
    }
    
    struct timeval tv;
    tv.tv_sec = timeout.count() / 1000;
    tv.tv_usec = (timeout.count() % 1000) * 1000;
    
    setsockopt(sockfd_, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    options_.recv_timeout = timeout;
}

void TcpSocket::set_send_timeout(const std::chrono::milliseconds& timeout) {
    options_.send_timeout = timeout;
    
    struct timeval tv;
    tv.tv_sec = static_cast<time_t>(timeout.count() / 1000);
    tv.tv_usec = static_cast<suseconds_t>((timeout.count() % 1000) * 1000);
    
    if (sockfd_ >= 0) {
        setsockopt(sockfd_, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
    }
}

void TcpSocket::apply_socket_options() {
    if (sockfd_ < 0) {
        return;
    }
    
    // 设置地址重用
    if (options_.reuse_address) {
        int opt = 1;
        setsockopt(sockfd_, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
    }
    
    // 设置保活
    if (options_.keep_alive) {
        int opt = 1;
        setsockopt(sockfd_, SOL_SOCKET, SO_KEEPALIVE, &opt, sizeof(opt));
    }
    
    // 设置发送缓冲区大小
    if (options_.send_buffer_size > 0) {
        setsockopt(sockfd_, SOL_SOCKET, SO_SNDBUF, &options_.send_buffer_size, sizeof(options_.send_buffer_size));
    }
    
    // 设置接收缓冲区大小
    if (options_.recv_buffer_size > 0) {
        setsockopt(sockfd_, SOL_SOCKET, SO_RCVBUF, &options_.recv_buffer_size, sizeof(options_.recv_buffer_size));
    }
    
    // 设置非阻塞模式
    if (options_.non_blocking) {
        set_non_blocking(true);
    }
}

void TcpSocket::get_socket_address(const struct sockaddr_in& addr, std::string& ip, uint16_t& port) {
    char ip_str[INET_ADDRSTRLEN] = {0};
    inet_ntop(AF_INET, &addr.sin_addr, ip_str, sizeof(ip_str));
    ip = ip_str;
    port = ntohs(addr.sin_port);
}

SocketError TcpSocket::get_last_error() const {
    return last_error_;
}

} // namespace network
} // namespace ft 