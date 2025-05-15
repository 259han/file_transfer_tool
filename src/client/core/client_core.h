#pragma once

#include <string>
#include <memory>
#include <future>
#include <thread>
#include <atomic>
#include "../../common/network/socket/tcp_socket.h"
#include "../../common/utils/logging/logger.h"

namespace ft {
namespace client {

/**
 * @brief 传输请求结构体
 */
struct TransferRequest {
    std::string local_file;    // 本地文件路径
    std::string remote_file;   // 远程文件路径
    size_t chunk_size;         // 分块大小
    bool resume;               // 是否断点续传
    
    TransferRequest()
        : local_file(""), 
          remote_file(""),
          chunk_size(1024 * 1024),  // 默认1MB
          resume(false) {
    }
};

/**
 * @brief 传输结果结构体
 */
struct TransferResult {
    bool success;                  // 是否成功
    std::string error_message;     // 错误信息
    size_t total_bytes;            // 总字节数
    size_t transferred_bytes;      // 已传输字节数
    double elapsed_seconds;        // 耗时(秒)
    
    TransferResult()
        : success(false),
          error_message(""),
          total_bytes(0),
          transferred_bytes(0),
          elapsed_seconds(0.0) {
    }
};

/**
 * @brief 服务器信息结构体
 */
struct ServerInfo {
    std::string host;          // 主机名或IP地址
    uint16_t port;             // 端口号
    std::string username;      // 用户名
    std::string password;      // 密码
    
    ServerInfo()
        : host("localhost"),
          port(12345),
          username(""),
          password("") {
    }
};

/**
 * @brief 客户端核心类
 */
class ClientCore {
public:
    /**
     * @brief 构造函数
     */
    ClientCore();
    
    /**
     * @brief 析构函数
     */
    ~ClientCore();
    
    /**
     * @brief 初始化客户端
     * @param log_level 日志级别
     * @return 是否初始化成功
     */
    bool initialize(utils::LogLevel log_level = utils::LogLevel::INFO);
    
    /**
     * @brief 连接到服务器
     * @param server 服务器信息
     * @return 是否连接成功
     */
    bool connect(const ServerInfo& server);
    
    /**
     * @brief 启动心跳线程
     */
    void start_heartbeat_thread();
    
    /**
     * @brief 发送心跳包检测连接状态
     * @return 心跳是否成功
     */  
    bool send_heartbeat();
    
    /**
     * @brief 断开与服务器的连接
     */
    void disconnect();
    
    /**
     * @brief 上传文件
     * @param request 传输请求
     * @return 传输结果
     */
    TransferResult upload(const TransferRequest& request);
    
    /**
     * @brief 异步上传文件
     * @param request 传输请求
     * @return 传输结果的future对象
     */
    std::future<TransferResult> upload_async(const TransferRequest& request);
    
    /**
     * @brief 下载文件
     * @param request 传输请求
     * @return 传输结果
     */
    TransferResult download(const TransferRequest& request);
    
    /**
     * @brief 异步下载文件
     * @param request 传输请求
     * @return 传输结果的future对象
     */
    std::future<TransferResult> download_async(const TransferRequest& request);
    
    /**
     * @brief 设置进度回调函数
     * @param callback 回调函数
     */
    void set_progress_callback(std::function<void(size_t, size_t)> callback);
    
    /**
     * @brief 是否已连接
     * @return 是否已连接
     */
    bool is_connected() const;
    
    /**
     * @brief 获取底层套接字
     * @return 套接字指针
     */
    network::TcpSocket* get_socket() const {
        return socket_.get();
    }
    
private:
    ServerInfo server_info_;
    std::unique_ptr<network::TcpSocket> socket_;
    std::function<void(size_t, size_t)> progress_callback_;
    bool is_connected_;
    std::thread heartbeat_thread_;      // 心跳线程
    std::atomic<bool> stop_heartbeat_;  // 停止心跳线程标志
};

} // namespace client
} // namespace ft 