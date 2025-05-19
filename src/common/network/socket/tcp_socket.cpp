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

namespace ft {
namespace network {

TcpSocket::TcpSocket(const SocketOptions& options)
    : sockfd_(-1),
      options_(options),
      connected_(false),
      local_ip_(""),
      local_port_(0),
      remote_ip_(""),
      remote_port_(0) {
    
    // 创建套接字
    sockfd_ = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd_ < 0) {
        throw std::runtime_error("Failed to create socket");
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
      remote_port_(0) {
    
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
            fprintf(stderr, "Failed to create socket in copy constructor: %s (errno=%d)\n", 
                    strerror(errno), errno);
            return;
        }
        
        // 应用套接字选项
        apply_socket_options();
        
        // 注意：复制构造函数不会复制连接状态，因为我们无法复制底层连接
        // 这里不会自动连接到相同的远程主机，需要调用者手动重新连接
        fprintf(stderr, "Socket copied but not connected. Call connect() to establish connection.\n");
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
                fprintf(stderr, "Failed to create socket in assignment operator: %s (errno=%d)\n", 
                        strerror(errno), errno);
                return *this;
            }
            
            // 应用套接字选项
            apply_socket_options();
            
            // 注意：赋值操作不会复制连接状态
            fprintf(stderr, "Socket assigned but not connected. Call connect() to establish connection.\n");
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
    fprintf(stderr, "TcpSocket move constructor: Moving fd=%d, connected=%d, remote=%s:%d to new object [%p->%p]\n", 
            sockfd_, connected_ ? 1 : 0, remote_ip_.c_str(), remote_port_, 
            static_cast<void*>(&other), static_cast<void*>(this));
    
    // 防止源对象析构时关闭socket
    int old_fd = other.sockfd_;
    other.sockfd_ = -1;
    other.connected_ = false;
    other.local_port_ = 0;
    other.remote_port_ = 0;
    
    fprintf(stderr, "TcpSocket move constructor: Source fd changed from %d to %d\n", old_fd, other.sockfd_);
}

TcpSocket& TcpSocket::operator=(TcpSocket&& other) noexcept {
    if (this != &other) {
        // 关闭现有套接字
        int old_fd = sockfd_;
        if (sockfd_ >= 0) {
            fprintf(stderr, "TcpSocket move assignment: Closing existing socket fd=%d\n", sockfd_);
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
        fprintf(stderr, "TcpSocket move assignment: Changed fd from %d to %d, connected=%d, remote=%s:%d [%p->%p]\n", 
                old_fd, sockfd_, connected_ ? 1 : 0, remote_ip_.c_str(), remote_port_, 
                static_cast<void*>(&other), static_cast<void*>(this));
        
        // 防止源对象析构时关闭socket
        int old_other_fd = other.sockfd_;
        other.sockfd_ = -1;
        other.connected_ = false;
        other.local_port_ = 0;
        other.remote_port_ = 0;
        
        fprintf(stderr, "TcpSocket move assignment: Source fd changed from %d to %d\n", old_other_fd, other.sockfd_);
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
    fprintf(stderr, "Accepting connections on %s:%d (fd=%d)...\n", 
            local_ip_.c_str(), local_port_, sockfd_);
            
    int client_fd = ::accept(sockfd_, (struct sockaddr*)&addr, &addr_len);
    if (client_fd < 0) {
        fprintf(stderr, "Accept failed: %s (errno=%d)\n", strerror(errno), errno);
        return SocketError::ACCEPT_FAILED;
    }
    
    fprintf(stderr, "Accepted connection, new socket fd=%d\n", client_fd);
    
    // 设置TCP选项，确保客户端连接的可靠性
    
    // 禁用Nagle算法
    int flag = 1;
    if (setsockopt(client_fd, IPPROTO_TCP, TCP_NODELAY, &flag, sizeof(flag)) < 0) {
        fprintf(stderr, "Warning: Failed to set TCP_NODELAY on client socket: %s (errno=%d)\n", 
                strerror(errno), errno);
        // 继续执行，这不是致命错误
    }
    
    // 设置TCP保活选项，更早检测断开的连接
    int keepalive = 1;
    int keepidle = 10;   // 10秒无数据传输就开始发送保活包
    int keepintvl = 1;   // 每1秒发送一次保活包
    int keepcnt = 3;     // 最多发送3次保活包
    
    // 启用保活
    if (setsockopt(client_fd, SOL_SOCKET, SO_KEEPALIVE, &keepalive, sizeof(keepalive)) < 0) {
        fprintf(stderr, "Warning: Failed to set SO_KEEPALIVE on client socket: %s (errno=%d)\n", 
                strerror(errno), errno);
    }
    
    // 设置保活参数 (仅适用于Linux系统)
#ifdef TCP_KEEPIDLE
    if (setsockopt(client_fd, IPPROTO_TCP, TCP_KEEPIDLE, &keepidle, sizeof(keepidle)) < 0) {
        fprintf(stderr, "Warning: Failed to set TCP_KEEPIDLE on client socket: %s (errno=%d)\n", 
                strerror(errno), errno);
    }
#endif

#ifdef TCP_KEEPINTVL
    if (setsockopt(client_fd, IPPROTO_TCP, TCP_KEEPINTVL, &keepintvl, sizeof(keepintvl)) < 0) {
        fprintf(stderr, "Warning: Failed to set TCP_KEEPINTVL on client socket: %s (errno=%d)\n", 
                strerror(errno), errno);
    }
#endif

#ifdef TCP_KEEPCNT
    if (setsockopt(client_fd, IPPROTO_TCP, TCP_KEEPCNT, &keepcnt, sizeof(keepcnt)) < 0) {
        fprintf(stderr, "Warning: Failed to set TCP_KEEPCNT on client socket: %s (errno=%d)\n", 
                strerror(errno), errno);
    }
#endif
    
    // 获取客户端地址信息
    std::string client_ip;
    uint16_t client_port;
    get_socket_address(addr, client_ip, client_port);
    
    fprintf(stderr, "Client connection details - address=%s:%d\n", client_ip.c_str(), client_port);
    
    // 关闭客户端套接字现有的fd，防止资源泄漏
    fprintf(stderr, "Closing client_socket existing fd=%d before assigning new fd=%d\n", 
            client_socket.sockfd_, client_fd);
    client_socket.close();
    
    // 记录当前客户端socket状态
    fprintf(stderr, "Before assignment - client_socket: fd=%d, connected=%d, remote=%s:%d\n",
            client_socket.sockfd_, client_socket.connected_ ? 1 : 0, 
            client_socket.remote_ip_.c_str(), client_socket.remote_port_);
    
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
    fprintf(stderr, "After assignment - client_socket: fd=%d, connected=%d, remote=%s:%d\n",
            client_socket.sockfd_, client_socket.connected_ ? 1 : 0, 
            client_socket.remote_ip_.c_str(), client_socket.remote_port_);
    
    // 验证客户端套接字是否仍然连接
    if (!client_socket.is_connected()) {
        fprintf(stderr, "Warning: Client socket not connected after accept and assignment\n");
    } else {
        fprintf(stderr, "Client socket successfully connected and assigned\n");
    }
    
    fprintf(stderr, "Accepted connection from %s:%d on socket fd=%d\n", 
            client_ip.c_str(), client_port, client_socket.sockfd_);
    
    return SocketError::SUCCESS;
}

SocketError TcpSocket::connect(const std::string& host, uint16_t port) {
    if (sockfd_ < 0) {
        return SocketError::INVALID_STATE;
    }
    
    struct sockaddr_in addr;
    std::memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    
    if (inet_pton(AF_INET, host.c_str(), &addr.sin_addr) <= 0) {
        // 尝试解析主机名
        struct hostent* he = gethostbyname(host.c_str());
        if (!he) {
            return SocketError::INVALID_ARGUMENT;
        }
        std::memcpy(&addr.sin_addr, he->h_addr_list[0], he->h_length);
    }
    
    // 可能需要关闭原有套接字并重新创建，确保清洁的TCP连接
    if (sockfd_ >= 0) {
        ::close(sockfd_);
    }
    
    // 重新创建套接字
    sockfd_ = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd_ < 0) {
        fprintf(stderr, "Failed to create socket: %s (errno=%d)\n", strerror(errno), errno);
        return SocketError::SOCKET_CREATE_FAILED;
    }
    
    // 重新应用套接字选项
    apply_socket_options();
    
    // 设置非阻塞模式进行连接，以支持超时
    bool orig_non_blocking = options_.non_blocking;
    set_non_blocking(true);
    
    fprintf(stderr, "Connecting to %s:%d (fd=%d)...\n", host.c_str(), port, sockfd_);
    int ret = ::connect(sockfd_, (struct sockaddr*)&addr, sizeof(addr));
    if (ret < 0 && errno != EINPROGRESS) {
        fprintf(stderr, "Connect failed: %s (errno=%d)\n", strerror(errno), errno);
        set_non_blocking(orig_non_blocking);
        return SocketError::CONNECT_FAILED;
    }
    
    // 等待连接完成或超时
    if (ret < 0 && errno == EINPROGRESS) {
        struct pollfd pfd;
        pfd.fd = sockfd_;
        pfd.events = POLLOUT;
        pfd.revents = 0;
        
        fprintf(stderr, "Waiting for connection to complete (timeout=%ld ms)...\n", 
                options_.connect_timeout.count());
                
        int poll_ret = poll(&pfd, 1, options_.connect_timeout.count());
        if (poll_ret <= 0) {
            set_non_blocking(orig_non_blocking);
            if (poll_ret == 0) {
                fprintf(stderr, "Connect timeout after %ld ms\n", options_.connect_timeout.count());
                return SocketError::TIMEOUT;
            } else {
                fprintf(stderr, "Poll failed during connect: %s (errno=%d)\n", 
                        strerror(errno), errno);
                return SocketError::CONNECT_FAILED;
            }
        }
        
        // 检查连接是否成功
        int error = 0;
        socklen_t len = sizeof(error);
        if (getsockopt(sockfd_, SOL_SOCKET, SO_ERROR, &error, &len) < 0 || error) {
            fprintf(stderr, "Failed to get socket options: %s (errno=%d)\n", 
                    error ? strerror(error) : strerror(errno), error ? error : errno);
            set_non_blocking(orig_non_blocking);
            return SocketError::CONNECT_FAILED;
        }
    }
    
    // 恢复原始的阻塞模式
    set_non_blocking(orig_non_blocking);
    
    // 设置TCP_NODELAY选项，禁用Nagle算法，减少延迟
    int flag = 1;
    if (setsockopt(sockfd_, IPPROTO_TCP, TCP_NODELAY, &flag, sizeof(flag)) < 0) {
        fprintf(stderr, "Warning: Failed to set TCP_NODELAY: %s (errno=%d)\n", 
                strerror(errno), errno);
        // 继续执行，这不是致命错误
    }
    
    // 设置TCP保活选项，更早检测断开的连接
    int keepalive = 1;
    int keepidle = 10;   // 10秒无数据传输就开始发送保活包
    int keepintvl = 1;   // 每1秒发送一次保活包
    int keepcnt = 3;     // 最多发送3次保活包
    
    // 启用保活
    if (setsockopt(sockfd_, SOL_SOCKET, SO_KEEPALIVE, &keepalive, sizeof(keepalive)) < 0) {
        fprintf(stderr, "Warning: Failed to set SO_KEEPALIVE: %s (errno=%d)\n", 
                strerror(errno), errno);
    }
    
    // 设置保活参数 (仅适用于Linux系统)
#ifdef TCP_KEEPIDLE
    if (setsockopt(sockfd_, IPPROTO_TCP, TCP_KEEPIDLE, &keepidle, sizeof(keepidle)) < 0) {
        fprintf(stderr, "Warning: Failed to set TCP_KEEPIDLE: %s (errno=%d)\n", 
                strerror(errno), errno);
    }
#endif

#ifdef TCP_KEEPINTVL
    if (setsockopt(sockfd_, IPPROTO_TCP, TCP_KEEPINTVL, &keepintvl, sizeof(keepintvl)) < 0) {
        fprintf(stderr, "Warning: Failed to set TCP_KEEPINTVL: %s (errno=%d)\n", 
                strerror(errno), errno);
    }
#endif

#ifdef TCP_KEEPCNT
    if (setsockopt(sockfd_, IPPROTO_TCP, TCP_KEEPCNT, &keepcnt, sizeof(keepcnt)) < 0) {
        fprintf(stderr, "Warning: Failed to set TCP_KEEPCNT: %s (errno=%d)\n", 
                strerror(errno), errno);
    }
#endif
    
    // 保存远程地址信息
    remote_ip_ = host;
    remote_port_ = port;
    connected_ = true;
    
    // 获取本地地址信息
    struct sockaddr_in local_addr;
    socklen_t addr_len = sizeof(local_addr);
    if (getsockname(sockfd_, (struct sockaddr*)&local_addr, &addr_len) == 0) {
        get_socket_address(local_addr, local_ip_, local_port_);
        fprintf(stderr, "Connected to %s:%d from local %s:%d (fd=%d)\n", 
                remote_ip_.c_str(), remote_port_, local_ip_.c_str(), local_port_, sockfd_);
    } else {
        fprintf(stderr, "Warning: Failed to get local address: %s (errno=%d)\n", 
                strerror(errno), errno);
        fprintf(stderr, "Connected to %s:%d (fd=%d)\n", 
                remote_ip_.c_str(), remote_port_, sockfd_);
    }
    
    return SocketError::SUCCESS;
}

SocketError TcpSocket::send(const void* data, size_t len, size_t& sent_len) {
    if (sockfd_ < 0) {
        return SocketError::INVALID_STATE;
    }
    
    if (!data || len == 0) {
        sent_len = 0;
        return SocketError::SUCCESS;
    }
    
    // 首先检查套接字是否仍然连接
    if (!check_connection_state_()) {
        fprintf(stderr, "Socket is not connected (fd=%d)\n", sockfd_);
        return SocketError::CLOSED;
    }
    
    // 等待套接字可写
    if (!options_.non_blocking) {
        struct pollfd pfd;
        pfd.fd = sockfd_;
        pfd.events = POLLOUT;
        pfd.revents = 0;
        
        int poll_ret = poll(&pfd, 1, options_.send_timeout.count());
        if (poll_ret <= 0) {
            if (poll_ret == 0) {
                return SocketError::TIMEOUT;
            } else {
                fprintf(stderr, "Poll failed with error: %s (errno=%d)\n", strerror(errno), errno);
                return SocketError::SEND_FAILED;
            }
        }
        
        // 检查套接字状态
        if ((pfd.revents & POLLERR) || (pfd.revents & POLLHUP) || (pfd.revents & POLLNVAL)) {
            int error = 0;
            socklen_t len = sizeof(error);
            getsockopt(sockfd_, SOL_SOCKET, SO_ERROR, &error, &len);
            fprintf(stderr, "Socket error during poll: %s (errno=%d)\n", strerror(error), error);
            if (pfd.revents & POLLHUP) {
                connected_ = false;  // 更新连接状态
                return SocketError::CLOSED;
            }
            return SocketError::SEND_FAILED;
        }
        
        if (!(pfd.revents & POLLOUT)) {
            fprintf(stderr, "Socket is not writable\n");
            return SocketError::SEND_FAILED;
        }
    }
    
    // 发送数据
    ssize_t ret = ::send(sockfd_, data, len, 0);
    if (ret < 0) {
        fprintf(stderr, "Send failed: %s (errno=%d)\n", strerror(errno), errno);
        if (errno == EPIPE || errno == ECONNRESET) {
            connected_ = false;  // 更新连接状态
            return SocketError::CLOSED;
        }
        return SocketError::SEND_FAILED;
    }
    
    sent_len = static_cast<size_t>(ret);
    return SocketError::SUCCESS;
}

SocketError TcpSocket::recv(void* buffer, size_t len, size_t& received_len) {
    if (sockfd_ < 0) {
        return SocketError::INVALID_STATE;
    }
    
    if (!buffer || len == 0) {
        received_len = 0;
        return SocketError::SUCCESS;
    }
    
    // 首先检查套接字是否仍然连接
    if (!check_connection_state_()) {
        fprintf(stderr, "Socket is not connected (fd=%d)\n", sockfd_);
        return SocketError::CLOSED;
    }
    
    // 等待套接字可读
    if (!options_.non_blocking) {
        struct pollfd pfd;
        pfd.fd = sockfd_;
        pfd.events = POLLIN;
        pfd.revents = 0;
        
        int poll_ret = poll(&pfd, 1, options_.recv_timeout.count());
        if (poll_ret <= 0) {
            if (poll_ret == 0) {
                fprintf(stderr, "Socket recv timeout after %ld ms\n", 
                        options_.recv_timeout.count());
                return SocketError::TIMEOUT;
            } else {
                fprintf(stderr, "Poll failed with error: %s (errno=%d)\n", strerror(errno), errno);
                return SocketError::RECV_FAILED;
            }
        }
        
        // 检查套接字状态
        if ((pfd.revents & POLLERR) || (pfd.revents & POLLHUP) || (pfd.revents & POLLNVAL)) {
            int error = 0;
            socklen_t len = sizeof(error);
            getsockopt(sockfd_, SOL_SOCKET, SO_ERROR, &error, &len);
            fprintf(stderr, "Socket error during poll: %s (errno=%d)\n", strerror(error), error);
            
            if (pfd.revents & POLLHUP) {
                connected_ = false;  // 标记连接已断开
                fprintf(stderr, "Socket recv detected POLLHUP, connection closed\n");
                return SocketError::CLOSED;
            }
            
            if (pfd.revents & POLLNVAL) {
                fprintf(stderr, "Socket recv detected POLLNVAL, invalid socket descriptor\n");
                connected_ = false;
                sockfd_ = -1;  // 无效的套接字描述符
                return SocketError::INVALID_STATE;
            }
            
            return SocketError::RECV_FAILED;
        }
        
        if (!(pfd.revents & POLLIN)) {
            fprintf(stderr, "Socket is not readable\n");
            return SocketError::RECV_FAILED;
        }
    }
    
    // 接收数据
    ssize_t ret = ::recv(sockfd_, buffer, len, 0);
    if (ret < 0) {
        fprintf(stderr, "Recv failed: %s (errno=%d)\n", strerror(errno), errno);
        
        if (errno == ECONNRESET || errno == EPIPE || errno == EBADF || errno == ENOTCONN) {
            connected_ = false;  // 标记连接已断开
            
            if (errno == EBADF) {
                sockfd_ = -1;  // 无效的套接字描述符
            }
            
            return SocketError::CLOSED;
        }
        
        return SocketError::RECV_FAILED;
    } else if (ret == 0) {
        // 连接对方已关闭
        fprintf(stderr, "Recv returned 0 bytes, connection closed by peer\n");
        connected_ = false;
        return SocketError::CLOSED;
    }
    
    received_len = static_cast<size_t>(ret);
    return SocketError::SUCCESS;
}

SocketError TcpSocket::send_all(const void* data, size_t len) {
    if (sockfd_ < 0) {
        return SocketError::INVALID_STATE;
    }
    
    if (!data || len == 0) {
        return SocketError::SUCCESS;
    }
    
    // 先验证连接状态
    if (!check_connection_state_()) {
        fprintf(stderr, "Socket send_all failed: Socket not connected\n");
        return SocketError::CLOSED;
    }
    
    const char* ptr = static_cast<const char*>(data);
    size_t remaining = len;
    size_t total_sent = 0;
    
    // 添加轻量级连接检查
    struct pollfd check_pfd;
    check_pfd.fd = sockfd_;
    check_pfd.events = POLLOUT;
    check_pfd.revents = 0;
    
    // 检查socket是否可写
    int check_poll_ret = poll(&check_pfd, 1, 0);
    if (check_poll_ret > 0) {
        if ((check_pfd.revents & POLLERR) || 
            (check_pfd.revents & POLLHUP) || 
            (check_pfd.revents & POLLNVAL)) {
            int error = 0;
            socklen_t len = sizeof(error);
            getsockopt(sockfd_, SOL_SOCKET, SO_ERROR, &error, &len);
            fprintf(stderr, "Socket send check detected error: %s (errno=%d)\n", 
                   strerror(error), error);
            
            connected_ = false;
            return SocketError::SEND_FAILED;
        }
    }
    
    while (remaining > 0) {
        size_t sent = 0;
        SocketError err = send(ptr, remaining, sent);
        if (err != SocketError::SUCCESS) {
            fprintf(stderr, "Socket send_all failed at %zu/%zu bytes: error %d\n", 
                   total_sent, len, static_cast<int>(err));
            
            // 在发送中途失败，标记连接状态
            if (err == SocketError::CLOSED) {
                connected_ = false;
            }
            
            return err;
        }
        
        ptr += sent;
        remaining -= sent;
        total_sent += sent;
    }
    
    return SocketError::SUCCESS;
}

SocketError TcpSocket::recv_all(void* buffer, size_t len) {
    if (sockfd_ < 0) {
        return SocketError::INVALID_STATE;
    }
    
    if (!buffer || len == 0) {
        return SocketError::SUCCESS;
    }
    
    char* ptr = static_cast<char*>(buffer);
    size_t remaining = len;
    size_t total_received = 0;
    int retry_count = 0;
    const int max_retries = 5;  // 增加重试次数
    
    while (remaining > 0) {
        // 每次接收前检查socket是否有效
        if (sockfd_ < 0 || !check_connection_state_()) {
            fprintf(stderr, "Socket recv_all failed: Socket not connected or invalid, total received: %zu/%zu bytes\n", 
                    total_received, len);
            return SocketError::CLOSED;
        }
        
        // 添加额外的连接检查 - 尝试轻量级的poll检测
        struct pollfd check_pfd;
        check_pfd.fd = sockfd_;
        check_pfd.events = POLLIN;
        check_pfd.revents = 0;
        
        // 快速检查连接状态（无超时）
        int check_poll_ret = poll(&check_pfd, 1, 0);
        if (check_poll_ret > 0) {
            if (check_pfd.revents & POLLERR) {
                int error = 0;
                socklen_t error_len = sizeof(error);
                getsockopt(sockfd_, SOL_SOCKET, SO_ERROR, &error, &error_len);
                
                fprintf(stderr, "Socket poll check detected error: %s (errno=%d)\n", 
                        strerror(error), error);
                
                connected_ = false;
                return SocketError::RECV_FAILED;
            }
            
            if (check_pfd.revents & POLLHUP) {
                fprintf(stderr, "Socket check detected POLLHUP, connection closed\n");
                connected_ = false;
                return SocketError::CLOSED;
            }
            
            if (check_pfd.revents & POLLNVAL) {
                fprintf(stderr, "Socket check detected POLLNVAL, invalid socket\n");
                connected_ = false;
                sockfd_ = -1;
                return SocketError::INVALID_STATE;
            }
        }
        
        size_t received = 0;
        SocketError err = recv(ptr, remaining, received);
        
        if (err != SocketError::SUCCESS) {
            // 如果接收到0字节，表示连接已关闭
            if (err == SocketError::CLOSED) {
                fprintf(stderr, "Socket recv_all failed: Connection closed by peer, total received: %zu/%zu bytes\n", 
                        total_received, len);
                connected_ = false;  // 标记为断开连接
                return err;
            }
            
            // 如果是超时错误，尝试重试几次
            if (err == SocketError::TIMEOUT && retry_count < max_retries) {
                retry_count++;
                fprintf(stderr, "Socket recv timeout, retry %d/%d, total received: %zu/%zu bytes\n", 
                        retry_count, max_retries, total_received, len);
                std::this_thread::sleep_for(std::chrono::milliseconds(100));  // 添加短暂延迟
                
                // 在重试前再次检查连接状态
                if (!check_connection_state_()) {
                    fprintf(stderr, "Socket disconnected during timeout retry\n");
                    return SocketError::CLOSED;
                }
                
                continue;
            }
            
            // 检查套接字是否仍然连接
            if (!connected_) {
                fprintf(stderr, "Socket recv_all failed: Socket disconnected, total received: %zu/%zu bytes\n", 
                        total_received, len);
                return SocketError::CLOSED;
            }
            
            // 记录详细信息到errno
            char err_buf[128] = {0};
            strerror_r(errno, err_buf, sizeof(err_buf));
            fprintf(stderr, "Socket recv_all failed: %s (errno=%d), total received: %zu/%zu bytes\n", 
                    err_buf, errno, total_received, len);
            
            // 如果发生EBADF或其他关键错误，立即将连接标记为断开
            if (errno == EBADF || errno == ENOTCONN || errno == ECONNRESET || errno == EPIPE) {
                connected_ = false;
                if (errno == EBADF) {
                    sockfd_ = -1;
                }
                fprintf(stderr, "Socket recv_all detected critical error, marking as disconnected\n");
                return SocketError::CLOSED;
            }
            
            return err;
        }
        
        // 如果接收到0字节，但没有错误，也认为连接已关闭
        if (received == 0) {
            fprintf(stderr, "Recv returned 0 bytes, connection closed by peer\n");
            connected_ = false;
            return SocketError::CLOSED;
        }
        
        // 重置重试计数
        retry_count = 0;
        
        ptr += received;
        remaining -= received;
        total_received += received;
    }
    
    return SocketError::SUCCESS;
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
        fprintf(stderr, "Basic connection check failed: sockfd_=%d, connected_=%d\n", sockfd_, connected_);
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
            fprintf(stderr, "Poll failed in check_connection_state: %s (errno=%d)\n", 
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
                    fprintf(stderr, "Socket error detected in check_connection_state: %s (errno=%d)\n", 
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
        fprintf(stderr, "Socket not readable/writable but no error: revents=%d\n", pfd.revents);
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
            fprintf(stderr, "Poll failed in is_connected: %s (errno=%d)\n", 
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
                    fprintf(stderr, "Socket error detected in is_connected: %s (errno=%d)\n", 
                            strerror(error), error);
                }
            }
        }
        
        // POLLHUP意味着连接已关闭
        if (pfd.revents & POLLHUP) {
            fprintf(stderr, "POLLHUP detected in is_connected (fd=%d)\n", fd);
            return false;
        }
        
        // POLLNVAL意味着socket描述符无效
        if (pfd.revents & POLLNVAL) {
            fprintf(stderr, "POLLNVAL detected in is_connected (fd=%d)\n", fd);
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
        fprintf(stderr, "Socket not readable/writable but no error: revents=%d\n", pfd.revents);
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
    if (sockfd_ < 0) {
        return;
    }
    
    struct timeval tv;
    tv.tv_sec = timeout.count() / 1000;
    tv.tv_usec = (timeout.count() % 1000) * 1000;
    
    setsockopt(sockfd_, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
    options_.send_timeout = timeout;
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
    char ip_str[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &addr.sin_addr, ip_str, sizeof(ip_str));
    ip = ip_str;
    port = ntohs(addr.sin_port);
}

} // namespace network
} // namespace ft 