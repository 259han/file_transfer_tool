#pragma once

#include <functional>
#include <chrono>

namespace ft {
namespace client {

/**
 * @brief 进度跟踪器类
 */
class ProgressTracker {
public:
    /**
     * @brief 构造函数
     * @param total_size 总大小
     * @param callback 回调函数
     */
    ProgressTracker(size_t total_size,
                  std::function<void(size_t, size_t)> callback = nullptr);
    
    /**
     * @brief 析构函数
     */
    ~ProgressTracker();
    
    /**
     * @brief 更新进度
     * @param current_size 当前大小
     * @return 传输速度(字节/秒)
     */
    double update(size_t current_size);
    
    /**
     * @brief 获取总大小
     * @return 总大小
     */
    size_t get_total_size() const;
    
    /**
     * @brief 获取当前大小
     * @return 当前大小
     */
    size_t get_current_size() const;
    
    /**
     * @brief 获取传输速度
     * @return 传输速度(字节/秒)
     */
    double get_speed() const;
    
    /**
     * @brief 获取估计剩余时间
     * @return 估计剩余时间(秒)
     */
    double get_eta() const;
    
    /**
     * @brief 获取进度百分比
     * @return 进度百分比(0-100)
     */
    double get_percentage() const;
    
private:
    size_t total_size_;
    size_t current_size_;
    std::chrono::steady_clock::time_point start_time_;
    std::chrono::steady_clock::time_point last_update_time_;
    double speed_;
    std::function<void(size_t, size_t)> callback_;
};

} // namespace client
} // namespace ft 