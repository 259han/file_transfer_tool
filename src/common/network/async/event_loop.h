#pragma once

#include <functional>
#include <vector>
#include <memory>
#include <chrono>
#include <unordered_map>
#include <atomic>
#include <thread>
#include <mutex>
#include "../../utils/threading/thread_pool.h"

#ifdef _WIN32
#include <winsock2.h>
#include <windows.h>
#else
#ifdef __APPLE__
#include <sys/event.h>
#include <sys/time.h>
#else
#include <sys/epoll.h>
#endif
#include <unistd.h>
#endif

namespace ft {
namespace network {

// 事件类型
enum class EventType {
    READ = 1,
    WRITE = 2,
    ERROR = 4,
    HANGUP = 8
};

// 事件回调函数
using EventCallback = std::function<void(int fd, EventType events)>;

// 事件数据结构
struct EventData {
    int fd;
    EventType events;
    EventCallback callback;
    bool active;
    
    EventData(int f, EventType e, EventCallback cb) 
        : fd(f), events(e), callback(std::move(cb)), active(true) {}
};

/**
 * @brief 跨平台事件循环器
 * 
 * 在Linux上使用epoll，macOS上使用kqueue，Windows上使用select
 * 提供统一的异步I/O事件处理接口
 */
class EventLoop {
public:
    EventLoop();
    ~EventLoop();
    
    // 禁用拷贝
    EventLoop(const EventLoop&) = delete;
    EventLoop& operator=(const EventLoop&) = delete;
    
    /**
     * @brief 初始化事件循环
     * @return 是否成功初始化
     */
    bool initialize();
    
    /**
     * @brief 添加文件描述符监听
     * @param fd 文件描述符
     * @param events 监听的事件类型
     * @param callback 事件回调函数
     * @return 是否成功添加
     */
    bool add_fd(int fd, EventType events, EventCallback callback);
    
    /**
     * @brief 修改文件描述符监听事件
     * @param fd 文件描述符
     * @param events 新的事件类型
     * @return 是否成功修改
     */
    bool modify_fd(int fd, EventType events);
    
    /**
     * @brief 移除文件描述符监听
     * @param fd 文件描述符
     * @return 是否成功移除
     */
    bool remove_fd(int fd);
    
    /**
     * @brief 运行事件循环（阻塞）
     * @param timeout_ms 超时时间（毫秒），-1表示无限等待
     * @return 处理的事件数量，-1表示错误
     */
    int run_once(int timeout_ms = -1);
    
    /**
     * @brief 停止事件循环
     */
    void stop();
    
    /**
     * @brief 检查是否正在运行
     */
    bool is_running() const { return running_; }
    
    /**
     * @brief 获取当前监听的文件描述符数量
     */
    size_t get_fd_count() const { 
        std::lock_guard<std::mutex> lock(events_mutex_); 
        return event_data_.size(); 
    }

private:
    // 平台特定的初始化
    bool platform_init();
    
    // 平台特定的清理
    void platform_cleanup();
    
    // 平台特定的添加fd
    bool platform_add_fd(int fd, EventType events);
    
    // 平台特定的修改fd
    bool platform_modify_fd(int fd, EventType events);
    
    // 平台特定的移除fd
    bool platform_remove_fd(int fd);
    
    // 平台特定的事件等待
    int platform_wait(int timeout_ms);
    
    // 转换事件类型到平台特定值
    uint32_t events_to_platform(EventType events);
    
    // 转换平台特定值到事件类型
    EventType platform_to_events(uint32_t platform_events);

private:
    std::atomic<bool> running_;
    std::atomic<bool> stop_requested_;
    
    // 事件数据映射
    mutable std::mutex events_mutex_;
    std::unordered_map<int, std::shared_ptr<EventData>> event_data_;
    
#ifdef _WIN32
    // Windows select implementation
    fd_set read_fds_;
    fd_set write_fds_;
    fd_set error_fds_;
    std::vector<int> active_fds_;
#elif defined(__APPLE__)
    // macOS kqueue implementation
    int kqueue_fd_;
    std::vector<struct kevent> events_buffer_;
#else
    // Linux epoll implementation
    int epoll_fd_;
    std::vector<struct epoll_event> events_buffer_;
#endif
    
    // 停止管道（用于中断阻塞的wait）
    int stop_pipe_[2];
    
    static const size_t MAX_EVENTS = 1024;
};

/**
 * @brief 异步I/O管理器
 * 
 * 封装EventLoop，提供更高级的异步I/O操作接口
 */
class AsyncIOManager {
public:
    AsyncIOManager();
    ~AsyncIOManager();
    
    /**
     * @brief 初始化异步I/O管理器
     * @param worker_threads 工作线程数量，0表示使用CPU核心数
     * @return 是否成功初始化
     */
    bool initialize(size_t worker_threads = 0);
    
    /**
     * @brief 启动异步I/O管理器
     * @return 是否成功启动
     */
    bool start();
    
    /**
     * @brief 停止异步I/O管理器
     */
    void stop();
    
    /**
     * @brief 异步接受连接
     * @param listen_fd 监听socket文件描述符
     * @param on_accept 接受连接回调 (client_fd) -> void
     */
    void async_accept(int listen_fd, std::function<void(int)> on_accept);
    
    /**
     * @brief 异步读取数据
     * @param fd 文件描述符
     * @param on_read 读取回调 (fd, available) -> void
     */
    void async_read(int fd, std::function<void(int, bool)> on_read);
    
    /**
     * @brief 异步写入数据
     * @param fd 文件描述符
     * @param on_write 写入回调 (fd, available) -> void
     */
    void async_write(int fd, std::function<void(int, bool)> on_write);
    
    /**
     * @brief 提交任务到工作线程池
     * @param task 任务函数
     */
    void submit_task(std::function<void()> task);
    
    /**
     * @brief 获取统计信息
     */
    struct Statistics {
        size_t active_connections;
        size_t total_events_processed;
        size_t pending_tasks;
        double events_per_second;
    };
    
    Statistics get_statistics() const;

private:
    void io_thread_func();
    
private:
    std::unique_ptr<EventLoop> event_loop_;
    std::thread io_thread_;
    
    // 工作线程池
    ft::utils::ThreadPool* worker_pool_;
    
    // 统计信息
    mutable std::mutex stats_mutex_;
    std::atomic<size_t> total_events_processed_;
    std::chrono::steady_clock::time_point start_time_;
    
    std::atomic<bool> running_;
};

} // namespace network
} // namespace ft