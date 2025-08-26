#include "event_loop.h"
#include "../../utils/logging/logger.h"
#include "../../utils/threading/thread_pool.h"
#include <algorithm>
#include <cstring>
#include <thread>

#ifndef _WIN32
#include <fcntl.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#endif

namespace ft {
namespace network {

// EventLoop implementation
EventLoop::EventLoop() 
    : running_(false), stop_requested_(false) {
    stop_pipe_[0] = stop_pipe_[1] = -1;
    
#ifdef _WIN32
    FD_ZERO(&read_fds_);
    FD_ZERO(&write_fds_);
    FD_ZERO(&error_fds_);
#elif defined(__APPLE__)
    kqueue_fd_ = -1;
    events_buffer_.resize(MAX_EVENTS);
#else
    epoll_fd_ = -1;
    events_buffer_.resize(MAX_EVENTS);
#endif
}

EventLoop::~EventLoop() {
    stop();
    platform_cleanup();
}

bool EventLoop::initialize() {
    LOG_INFO("Initializing EventLoop...");
    
    if (!platform_init()) {
        LOG_ERROR("Failed to initialize platform-specific event mechanism");
        return false;
    }
    
    // 创建停止管道 - 简化版本
#ifndef _WIN32
    if (pipe(stop_pipe_) == -1) {
        LOG_ERROR("Failed to create stop pipe: %s", strerror(errno));
        return false;
    }
    
    // 设置为非阻塞
    if (fcntl(stop_pipe_[0], F_SETFL, O_NONBLOCK) == -1 ||
        fcntl(stop_pipe_[1], F_SETFL, O_NONBLOCK) == -1) {
        LOG_ERROR("Failed to set stop pipe non-blocking: %s", strerror(errno));
        close(stop_pipe_[0]);
        close(stop_pipe_[1]);
        return false;
    }
#endif
    
    LOG_INFO("EventLoop initialized successfully");
    return true;
}

bool EventLoop::add_fd(int fd, EventType events, EventCallback callback) {
    if (fd < 0) {
        LOG_ERROR("Invalid file descriptor: %d", fd);
        return false;
    }
    
    std::lock_guard<std::mutex> lock(events_mutex_);
    
    // 检查是否已存在
    if (event_data_.find(fd) != event_data_.end()) {
        LOG_WARNING("File descriptor %d already exists in event loop", fd);
        return false;
    }
    
    // 添加到平台特定的事件机制
    if (!platform_add_fd(fd, events)) {
        LOG_ERROR("Failed to add fd %d to platform event mechanism", fd);
        return false;
    }
    
    // 保存事件数据
    event_data_[fd] = std::make_shared<EventData>(fd, events, std::move(callback));
    
    LOG_DEBUG("Added fd %d to event loop (events: %d)", fd, static_cast<int>(events));
    return true;
}

bool EventLoop::modify_fd(int fd, EventType events) {
    std::lock_guard<std::mutex> lock(events_mutex_);
    
    auto it = event_data_.find(fd);
    if (it == event_data_.end()) {
        LOG_ERROR("File descriptor %d not found in event loop", fd);
        return false;
    }
    
    if (!platform_modify_fd(fd, events)) {
        LOG_ERROR("Failed to modify fd %d in platform event mechanism", fd);
        return false;
    }
    
    it->second->events = events;
    LOG_DEBUG("Modified fd %d events to %d", fd, static_cast<int>(events));
    return true;
}

bool EventLoop::remove_fd(int fd) {
    std::lock_guard<std::mutex> lock(events_mutex_);
    
    auto it = event_data_.find(fd);
    if (it == event_data_.end()) {
        LOG_WARNING("File descriptor %d not found in event loop", fd);
        return false;
    }
    
    if (!platform_remove_fd(fd)) {
        LOG_ERROR("Failed to remove fd %d from platform event mechanism", fd);
        return false;
    }
    
    event_data_.erase(it);
    LOG_DEBUG("Removed fd %d from event loop", fd);
    return true;
}

int EventLoop::run_once(int timeout_ms) {
    if (!running_) {
        running_ = true;
    }
    
    if (stop_requested_) {
        running_ = false;
        return 0;
    }
    
    // 等待事件
    int event_count = platform_wait(timeout_ms);
    if (event_count < 0) {
        if (!stop_requested_) {
            LOG_ERROR("Event wait failed");
        }
        running_ = false;
        return -1;
    }
    
    if (event_count == 0) {
        // 超时，没有事件
        return 0;
    }
    
    LOG_DEBUG("EventLoop: processing %d events", event_count);
    return event_count;
}

void EventLoop::stop() {
    if (!running_ && !stop_requested_) {
        return;
    }
    
    LOG_INFO("Stopping EventLoop...");
    stop_requested_ = true;
    
    // 通过管道发送停止信号
    if (stop_pipe_[1] != -1) {
        char signal = 1;
#ifdef _WIN32
        send(stop_pipe_[1], &signal, 1, 0);
#else
        write(stop_pipe_[1], &signal, 1);
#endif
    }
    
    running_ = false;
}

// Platform-specific implementations

#if defined(__linux__)
// Linux implementation using epoll
bool EventLoop::platform_init() {
    epoll_fd_ = epoll_create1(EPOLL_CLOEXEC);
    if (epoll_fd_ == -1) {
        LOG_ERROR("Failed to create epoll: %s", strerror(errno));
        return false;
    }
    return true;
}

void EventLoop::platform_cleanup() {
    if (epoll_fd_ != -1) {
        close(epoll_fd_);
        epoll_fd_ = -1;
    }
    if (stop_pipe_[0] != -1) {
        close(stop_pipe_[0]);
        stop_pipe_[0] = -1;
    }
    if (stop_pipe_[1] != -1) {
        close(stop_pipe_[1]);
        stop_pipe_[1] = -1;
    }
}

bool EventLoop::platform_add_fd(int fd, EventType events) {
    struct epoll_event ev;
    ev.events = events_to_platform(events) | EPOLLET;  // 使用边缘触发
    ev.data.fd = fd;
    
    if (epoll_ctl(epoll_fd_, EPOLL_CTL_ADD, fd, &ev) == -1) {
        LOG_ERROR("Failed to add fd %d to epoll: %s", fd, strerror(errno));
        return false;
    }
    
    return true;
}

bool EventLoop::platform_modify_fd(int fd, EventType events) {
    struct epoll_event ev;
    ev.events = events_to_platform(events) | EPOLLET;  // 使用边缘触发
    ev.data.fd = fd;
    
    if (epoll_ctl(epoll_fd_, EPOLL_CTL_MOD, fd, &ev) == -1) {
        LOG_ERROR("Failed to modify fd %d in epoll: %s", fd, strerror(errno));
        return false;
    }
    
    return true;
}

bool EventLoop::platform_remove_fd(int fd) {
    if (epoll_ctl(epoll_fd_, EPOLL_CTL_DEL, fd, nullptr) == -1) {
        LOG_ERROR("Failed to remove fd %d from epoll: %s", fd, strerror(errno));
        return false;
    }
    return true;
}

uint32_t EventLoop::events_to_platform(EventType events) {
    uint32_t platform_events = 0;
    
    if (static_cast<int>(events) & static_cast<int>(EventType::READ)) {
        platform_events |= EPOLLIN;
    }
    if (static_cast<int>(events) & static_cast<int>(EventType::WRITE)) {
        platform_events |= EPOLLOUT;
    }
    if (static_cast<int>(events) & static_cast<int>(EventType::ERROR)) {
        platform_events |= EPOLLERR;
    }
    if (static_cast<int>(events) & static_cast<int>(EventType::HANGUP)) {
        platform_events |= EPOLLHUP;
    }
    
    return platform_events;
}

EventType EventLoop::platform_to_events(uint32_t platform_events) {
    EventType events = static_cast<EventType>(0);
    
    if (platform_events & EPOLLIN) {
        events = static_cast<EventType>(static_cast<int>(events) | static_cast<int>(EventType::READ));
    }
    if (platform_events & EPOLLOUT) {
        events = static_cast<EventType>(static_cast<int>(events) | static_cast<int>(EventType::WRITE));
    }
    if (platform_events & EPOLLERR) {
        events = static_cast<EventType>(static_cast<int>(events) | static_cast<int>(EventType::ERROR));
    }
    if (platform_events & EPOLLHUP) {
        events = static_cast<EventType>(static_cast<int>(events) | static_cast<int>(EventType::HANGUP));
    }
    
    return events;
}

int EventLoop::platform_wait(int timeout_ms) {
    int event_count = epoll_wait(epoll_fd_, events_buffer_.data(), events_buffer_.size(), timeout_ms);
    if (event_count <= 0) {
        return event_count;
    }
    
    // 处理事件
    std::vector<std::pair<int, EventType>> events_to_process;
    
    for (int i = 0; i < event_count; i++) {
        const struct epoll_event& ev = events_buffer_[i];
        int fd = ev.data.fd;
        EventType triggered_events = platform_to_events(ev.events);
        
        events_to_process.emplace_back(fd, triggered_events);
    }
    
    // 执行回调
    for (const auto& event : events_to_process) {
        int fd = event.first;
        EventType events = event.second;
        
        std::shared_ptr<EventData> event_data;
        {
            std::lock_guard<std::mutex> lock(events_mutex_);
            auto it = event_data_.find(fd);
            if (it != event_data_.end()) {
                event_data = it->second;
            }
        }
        
        if (event_data && event_data->active) {
            try {
                event_data->callback(fd, events);
            } catch (const std::exception& e) {
                LOG_ERROR("Event callback exception for fd %d: %s", fd, e.what());
            }
        }
    }
    
    return event_count;
}

#else
// 简化的默认实现，用于其他平台
bool EventLoop::platform_init() {
    LOG_WARNING("Using simplified event loop implementation");
    return true;
}

void EventLoop::platform_cleanup() {
    if (stop_pipe_[0] != -1) {
        close(stop_pipe_[0]);
        stop_pipe_[0] = -1;
    }
    if (stop_pipe_[1] != -1) {
        close(stop_pipe_[1]);
        stop_pipe_[1] = -1;
    }
}

bool EventLoop::platform_add_fd(int fd, EventType events) {
    return true;  // 简化实现
}

bool EventLoop::platform_modify_fd(int fd, EventType events) {
    return true;  // 简化实现
}

bool EventLoop::platform_remove_fd(int fd) {
    return true;  // 简化实现
}

int EventLoop::platform_wait(int timeout_ms) {
    // 简化实现：只是等待
    std::this_thread::sleep_for(std::chrono::milliseconds(timeout_ms > 0 ? timeout_ms : 100));
    return 0;
}

uint32_t EventLoop::events_to_platform(EventType events) {
    return static_cast<uint32_t>(events);
}

EventType EventLoop::platform_to_events(uint32_t platform_events) {
    return static_cast<EventType>(platform_events);
}

#endif

// AsyncIOManager implementation
AsyncIOManager::AsyncIOManager() 
    : event_loop_(std::make_unique<EventLoop>()),
      worker_pool_(nullptr),
      total_events_processed_(0),
      running_(false) {
}

AsyncIOManager::~AsyncIOManager() {
    stop();
}

bool AsyncIOManager::initialize(size_t worker_threads) {
    if (!event_loop_->initialize()) {
        LOG_ERROR("Failed to initialize EventLoop");
        return false;
    }
    
    // 创建工作线程池
    if (worker_threads == 0) {
        worker_threads = std::thread::hardware_concurrency();
        if (worker_threads == 0) worker_threads = 4;  // 默认4个线程
    }
    
    worker_pool_ = new utils::ThreadPool(worker_threads);
    
    LOG_INFO("AsyncIOManager initialized with %zu worker threads", worker_threads);
    start_time_ = std::chrono::steady_clock::now();
    return true;
}

bool AsyncIOManager::start() {
    if (running_) {
        LOG_WARNING("AsyncIOManager is already running");
        return false;
    }
    
    running_ = true;
    
    // 启动I/O线程
    io_thread_ = std::thread(&AsyncIOManager::io_thread_func, this);
    
    LOG_INFO("AsyncIOManager started");
    return true;
}

void AsyncIOManager::stop() {
    if (!running_) {
        return;
    }
    
    LOG_INFO("Stopping AsyncIOManager...");
    running_ = false;
    
    // 停止事件循环
    event_loop_->stop();
    
    // 等待I/O线程结束
    if (io_thread_.joinable()) {
        io_thread_.join();
    }
    
    // 停止工作线程池
    if (worker_pool_) {
        delete worker_pool_;
        worker_pool_ = nullptr;
    }
    
    LOG_INFO("AsyncIOManager stopped");
}

void AsyncIOManager::async_accept(int listen_fd, std::function<void(int)> on_accept) {
    auto callback = [this, on_accept = std::move(on_accept)](int fd, EventType events) {
        if (static_cast<int>(events) & static_cast<int>(EventType::READ)) {
            // 有新连接到达
            on_accept(fd);
        }
        if (static_cast<int>(events) & (static_cast<int>(EventType::ERROR) | static_cast<int>(EventType::HANGUP))) {
            LOG_ERROR("Listen socket error or hangup on fd %d", fd);
        }
    };
    
    event_loop_->add_fd(listen_fd, EventType::READ, std::move(callback));
}

void AsyncIOManager::async_read(int fd, std::function<void(int, bool)> on_read) {
    auto callback = [this, on_read = std::move(on_read)](int fd, EventType events) {
        bool available = static_cast<int>(events) & static_cast<int>(EventType::READ);
        on_read(fd, available);
        
        total_events_processed_++;
    };
    
    event_loop_->add_fd(fd, EventType::READ, std::move(callback));
}

void AsyncIOManager::async_write(int fd, std::function<void(int, bool)> on_write) {
    auto callback = [this, on_write = std::move(on_write)](int fd, EventType events) {
        bool available = static_cast<int>(events) & static_cast<int>(EventType::WRITE);
        on_write(fd, available);
        
        total_events_processed_++;
    };
    
    event_loop_->add_fd(fd, EventType::WRITE, std::move(callback));
}

void AsyncIOManager::submit_task(std::function<void()> task) {
    if (worker_pool_) {
        worker_pool_->enqueue(std::move(task));
    }
}

AsyncIOManager::Statistics AsyncIOManager::get_statistics() const {
    Statistics stats;
    stats.active_connections = event_loop_->get_fd_count();
    stats.total_events_processed = total_events_processed_;
    stats.pending_tasks = worker_pool_ ? worker_pool_->get_pending_tasks() : 0;
    
    auto now = std::chrono::steady_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::seconds>(now - start_time_).count();
    stats.events_per_second = duration > 0 ? static_cast<double>(stats.total_events_processed) / duration : 0.0;
    
    return stats;
}

void AsyncIOManager::io_thread_func() {
    LOG_INFO("AsyncIOManager I/O thread started");
    
    while (running_) {
        int event_count = event_loop_->run_once(100);  // 100ms超时
        if (event_count < 0) {
            if (running_) {
                LOG_ERROR("Event loop error, stopping I/O thread");
            }
            break;
        }
    }
    
    LOG_INFO("AsyncIOManager I/O thread stopped");
}

} // namespace network
} // namespace ft 