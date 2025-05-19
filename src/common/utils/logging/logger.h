#pragma once

#include <string>
#include <fstream>
#include <iostream>
#include <mutex>
#include <vector>
#include <chrono>
#include <functional>

namespace ft {
namespace utils {

/**
 * @brief 日志级别
 */
enum class LogLevel {
    DEBUG = 0,  // 调试信息
    INFO,       // 普通信息
    WARNING,    // 警告信息
    ERROR,      // 错误信息
    FATAL       // 致命错误
};

/**
 * @brief 日志记录器类
 */
class Logger {
public:
    /**
     * @brief 获取单例实例
     * @return 日志记录器实例
     */
    static Logger& instance();
    
    /**
     * @brief 初始化日志记录器
     * @param level 日志级别
     * @param log_to_console 是否输出到控制台
     * @param log_file 日志文件路径，为空则不记录到文件
     * @param max_file_size 日志文件最大大小，单位字节
     * @return 是否初始化成功
     */
    bool init(LogLevel level = LogLevel::INFO, 
              bool log_to_console = true, 
              const std::string& log_file = "", 
              size_t max_file_size = 10 * 1024 * 1024);
    
    /**
     * @brief 设置日志级别
     * @param level 日志级别
     */
    void set_level(LogLevel level);
    
    /**
     * @brief 获取日志级别
     * @return 日志级别
     */
    LogLevel get_level() const;
    
    /**
     * @brief 设置是否输出到控制台
     * @param enable 是否输出到控制台
     */
    void set_console_output(bool enable);
    
    /**
     * @brief 设置日志文件
     * @param log_file 日志文件路径，为空则不记录到文件
     * @param max_file_size 日志文件最大大小，单位字节
     * @return 是否设置成功
     */
    bool set_file_output(const std::string& log_file, size_t max_file_size = 10 * 1024 * 1024);
    
    /**
     * @brief 记录日志
     * @param level 日志级别
     * @param file 源文件
     * @param line 行号
     * @param func 函数名
     * @param format 格式化字符串
     * @param args 参数列表
     */
    template<typename... Args>
    void log(LogLevel level, const char* file, int line, const char* func, const char* format, Args&&... args);
    
    /**
     * @brief 添加日志监听器
     * @param listener 监听器函数
     */
    void add_listener(std::function<void(LogLevel, const std::string&)> listener);
    
    /**
     * @brief 清空监听器
     */
    void clear_listeners();
    
private:
    /**
     * @brief 构造函数
     */
    Logger();
    
    /**
     * @brief 析构函数
     */
    ~Logger();
    
    /**
     * @brief 格式化日志消息
     * @param level 日志级别
     * @param file 源文件
     * @param line 行号
     * @param func 函数名
     * @param content 日志内容
     * @return 格式化后的日志消息
     */
    std::string format_log(LogLevel level, const char* file, int line, const char* func, const std::string& content);
    
    /**
     * @brief 写入日志到文件
     * @param message 日志消息
     */
    void write_to_file(const std::string& message);
    
    /**
     * @brief 日志级别转字符串
     * @param level 日志级别
     * @return 日志级别字符串
     */
    static std::string level_to_string(LogLevel level);
    
    /**
     * @brief 获取当前时间字符串
     * @return 当前时间字符串
     */
    static std::string get_current_time();
    
    /**
     * @brief 格式化字符串
     * @param format 格式化字符串
     * @param args 参数列表
     * @return 格式化后的字符串
     */
    template<typename... Args>
    static std::string format_string(const char* format, Args&&... args);
    
private:
    LogLevel level_;
    bool log_to_console_;
    std::string log_file_;
    size_t max_file_size_;
    std::ofstream file_stream_;
    std::mutex mutex_;
    std::vector<std::function<void(LogLevel, const std::string&)>> listeners_;
};

// 日志宏定义，方便使用
#define LOG_DEBUG(format, ...) ft::utils::Logger::instance().log(ft::utils::LogLevel::DEBUG, __FILE__, __LINE__, __FUNCTION__, format, ##__VA_ARGS__)
#define LOG_INFO(format, ...) ft::utils::Logger::instance().log(ft::utils::LogLevel::INFO, __FILE__, __LINE__, __FUNCTION__, format, ##__VA_ARGS__)
#define LOG_WARNING(format, ...) ft::utils::Logger::instance().log(ft::utils::LogLevel::WARNING, __FILE__, __LINE__, __FUNCTION__, format, ##__VA_ARGS__)
#define LOG_ERROR(format, ...) ft::utils::Logger::instance().log(ft::utils::LogLevel::ERROR, __FILE__, __LINE__, __FUNCTION__, format, ##__VA_ARGS__)
#define LOG_FATAL(format, ...) ft::utils::Logger::instance().log(ft::utils::LogLevel::FATAL, __FILE__, __LINE__, __FUNCTION__, format, ##__VA_ARGS__)

// 模板函数实现
template<typename... Args>
void Logger::log(LogLevel level, const char* file, int line, const char* func, const char* format, Args&&... args) {
    if (level < level_) {
        return;
    }
    
    // 格式化日志内容
    std::string content = format_string(format, std::forward<Args>(args)...);
    
    // 格式化完整日志消息
    std::string message = format_log(level, file, line, func, content);
    
    // 加锁保护
    std::lock_guard<std::mutex> lock(mutex_);
    
    // 输出到控制台
    if (log_to_console_) {
        // 根据级别设置不同颜色
        switch (level) {
            case LogLevel::DEBUG:
                std::cout << "\033[37m" << message << "\033[0m" << std::endl;
                break;
            case LogLevel::INFO:
                std::cout << "\033[32m" << message << "\033[0m" << std::endl;
                break;
            case LogLevel::WARNING:
                std::cout << "\033[33m" << message << "\033[0m" << std::endl;
                break;
            case LogLevel::ERROR:
                std::cout << "\033[31m" << message << "\033[0m" << std::endl;
                break;
            case LogLevel::FATAL:
                std::cout << "\033[35m" << message << "\033[0m" << std::endl;
                break;
        }
    }
    
    // 写入日志文件
    if (!log_file_.empty()) {
        write_to_file(message);
    }
    
    // 通知监听器
    for (const auto& listener : listeners_) {
        listener(level, message);
    }
}

template<typename... Args>
std::string Logger::format_string(const char* format, Args&&... args) {
    char buffer[1024];
    
    // 修复：当没有参数时，直接返回格式字符串
    if constexpr(sizeof...(args) == 0) {
        return std::string(format);
    } else {
        snprintf(buffer, sizeof(buffer), format, std::forward<Args>(args)...);
        return std::string(buffer);
    }
}

} // namespace utils
} // namespace ft 