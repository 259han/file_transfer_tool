#pragma once

#include <functional>
#include <vector>
#include <thread>
#include <mutex>
#include <condition_variable>
#include <atomic>

namespace ft {
namespace network {

/**
 * @brief 事件循环类
 */
class EventLoop {
public:
    /**
     * @brief 构造函数
     */
    EventLoop();
    
    /**
     * @brief 析构函数
     */
    ~EventLoop();
    
    /**
     * @brief 启动事件循环
     */
    void start();
    
    /**
     * @brief 停止事件循环
     */
    void stop();
    
    /**
     * @brief 添加任务
     * @param task 任务函数
     */
    void post(std::function<void()> task);
    
private:
    /**
     * @brief 线程函数
     */
    void thread_func();
    
private:
    std::thread thread_;
    std::vector<std::function<void()>> tasks_;
    std::mutex mutex_;
    std::condition_variable cv_;
    std::atomic<bool> running_;
};

} // namespace network
} // namespace ft 