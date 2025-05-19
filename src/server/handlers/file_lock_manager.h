#pragma once

#include <string>
#include <mutex>
#include <unordered_map>
#include <shared_mutex>
#include <fcntl.h>
#include <unistd.h>
#include <sys/file.h>
#include "../../common/utils/logging/logger.h"

namespace ft {
namespace server {

/**
 * @brief 文件锁类型
 */
enum class FileLockType {
    SHARED,     // 共享锁（读锁）
    EXCLUSIVE   // 独占锁（写锁）
};

/**
 * @brief 文件锁信息
 */
struct FileLockInfo {
    int fd;                 // 文件描述符
    FileLockType lock_type; // 锁类型
    
    FileLockInfo() : fd(-1), lock_type(FileLockType::SHARED) {}
    FileLockInfo(int fd, FileLockType type) : fd(fd), lock_type(type) {}
};

/**
 * @brief 文件锁管理器类
 * 
 * 负责管理文件锁，支持读写锁，确保多客户端并发访问安全
 */
class FileLockManager {
public:
    /**
     * @brief 获取单例实例
     * @return 文件锁管理器实例
     */
    static FileLockManager& instance();
    
    /**
     * @brief 获取文件锁
     * @param file_path 文件路径
     * @param lock_type 锁类型
     * @return 是否成功获取锁
     */
    bool acquire_lock(const std::string& file_path, FileLockType lock_type);
    
    /**
     * @brief 释放文件锁
     * @param file_path 文件路径
     * @return 是否成功释放锁
     */
    bool release_lock(const std::string& file_path);
    
    /**
     * @brief 检查文件是否已锁定
     * @param file_path 文件路径
     * @return 是否已锁定
     */
    bool is_locked(const std::string& file_path);

private:
    /**
     * @brief 构造函数
     */
    FileLockManager();
    
    /**
     * @brief 析构函数
     */
    ~FileLockManager();
    
    // 禁止拷贝和赋值
    FileLockManager(const FileLockManager&) = delete;
    FileLockManager& operator=(const FileLockManager&) = delete;

private:
    std::mutex mutex_;                                     // 保护锁映射
    std::unordered_map<std::string, FileLockInfo> locks_; // 文件锁映射表
};

} // namespace server
} // namespace ft 