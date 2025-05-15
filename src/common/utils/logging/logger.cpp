#include "logger.h"
#include <chrono>
#include <ctime>
#include <iomanip>
#include <sstream>
#include <filesystem>

namespace fs = std::filesystem;

namespace ft {
namespace utils {

Logger& Logger::instance() {
    static Logger instance;
    return instance;
}

Logger::Logger()
    : level_(LogLevel::INFO),
      log_to_console_(true),
      log_file_(""),
      max_file_size_(10 * 1024 * 1024),
      file_stream_(),
      mutex_(),
      listeners_() {
}

Logger::~Logger() {
    if (file_stream_.is_open()) {
        file_stream_.close();
    }
}

bool Logger::init(LogLevel level, bool log_to_console, const std::string& log_file, size_t max_file_size) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    level_ = level;
    log_to_console_ = log_to_console;
    
    // 设置日志文件
    if (!log_file.empty()) {
        return set_file_output(log_file, max_file_size);
    }
    
    return true;
}

void Logger::set_level(LogLevel level) {
    std::lock_guard<std::mutex> lock(mutex_);
    level_ = level;
}

LogLevel Logger::get_level() const {
    return level_;
}

void Logger::set_console_output(bool enable) {
    std::lock_guard<std::mutex> lock(mutex_);
    log_to_console_ = enable;
}

bool Logger::set_file_output(const std::string& log_file, size_t max_file_size) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    // 关闭原来的文件流
    if (file_stream_.is_open()) {
        file_stream_.close();
    }
    
    // 设置新的文件路径和最大大小
    log_file_ = log_file;
    max_file_size_ = max_file_size;
    
    // 如果文件路径为空，则不记录到文件
    if (log_file_.empty()) {
        return true;
    }
    
    // 确保目录存在
    fs::path path(log_file_);
    try {
        if (!path.parent_path().empty()) {
            fs::create_directories(path.parent_path());
        }
    } catch (const std::exception& e) {
        std::cerr << "Create log directory failed: " << e.what() << std::endl;
        return false;
    }
    
    // 打开文件
    file_stream_.open(log_file_, std::ios::app);
    if (!file_stream_.is_open()) {
        log_file_ = "";
        return false;
    }
    
    return true;
}

void Logger::add_listener(std::function<void(LogLevel, const std::string&)> listener) {
    std::lock_guard<std::mutex> lock(mutex_);
    listeners_.push_back(listener);
}

void Logger::clear_listeners() {
    std::lock_guard<std::mutex> lock(mutex_);
    listeners_.clear();
}

std::string Logger::format_log(LogLevel level, const char* file, int line, const char* func, const std::string& content) {
    // 提取文件名
    std::string filename = file;
    size_t pos = filename.find_last_of("/\\");
    if (pos != std::string::npos) {
        filename = filename.substr(pos + 1);
    }
    
    // 格式化日志
    std::stringstream ss;
    ss << "[" << get_current_time() << "] "
       << "[" << level_to_string(level) << "] "
       << "[" << filename << ":" << line << ":" << func << "] "
       << content;
    
    return ss.str();
}

void Logger::write_to_file(const std::string& message) {
    // 检查文件是否打开
    if (!file_stream_.is_open()) {
        if (!set_file_output(log_file_, max_file_size_)) {
            return;
        }
    }
    
    // 检查文件大小
    file_stream_.seekp(0, std::ios::end);
    if (file_stream_.tellp() > static_cast<std::streampos>(max_file_size_)) {
        // 备份旧文件
        file_stream_.close();
        
        // 备份文件名，加上时间戳
        std::string backup_file = log_file_ + "." + get_current_time();
        std::replace(backup_file.begin(), backup_file.end(), ':', '-');
        
        // 重命名文件
        try {
            fs::rename(log_file_, backup_file);
        } catch (const std::exception& e) {
            std::cerr << "Rename log file failed: " << e.what() << std::endl;
        }
        
        // 重新打开文件
        file_stream_.open(log_file_, std::ios::out);
        if (!file_stream_.is_open()) {
            log_file_ = "";
            return;
        }
    }
    
    // 写入日志
    file_stream_ << message << std::endl;
    file_stream_.flush();
}

std::string Logger::level_to_string(LogLevel level) {
    switch (level) {
        case LogLevel::DEBUG:
            return "DEBUG";
        case LogLevel::INFO:
            return "INFO";
        case LogLevel::WARNING:
            return "WARNING";
        case LogLevel::ERROR:
            return "ERROR";
        case LogLevel::FATAL:
            return "FATAL";
        default:
            return "UNKNOWN";
    }
}

std::string Logger::get_current_time() {
    auto now = std::chrono::system_clock::now();
    auto now_time = std::chrono::system_clock::to_time_t(now);
    auto now_ms = std::chrono::duration_cast<std::chrono::milliseconds>(now.time_since_epoch()) % 1000;
    
    std::stringstream ss;
    ss << std::put_time(std::localtime(&now_time), "%Y-%m-%d %H:%M:%S");
    ss << '.' << std::setfill('0') << std::setw(3) << now_ms.count();
    
    return ss.str();
}

} // namespace utils
} // namespace ft 