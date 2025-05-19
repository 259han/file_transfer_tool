#include "file_lock_manager.h"
#include <filesystem>
#include <string>
#include <sys/stat.h>
#include <errno.h>
#include <cstring>
#include <thread>
#include <chrono>

namespace fs = std::filesystem;

namespace ft {
namespace server {

// 单例实现
FileLockManager& FileLockManager::instance() {
    static FileLockManager instance;
    return instance;
}

FileLockManager::FileLockManager() 
    : mutex_(), 
      locks_() {
}

FileLockManager::~FileLockManager() {
    // 释放所有文件锁
    std::lock_guard<std::mutex> lock(mutex_);
    
    for (auto& pair : locks_) {
        // 关闭文件描述符会自动释放锁
        if (pair.second.fd >= 0) {
            close(pair.second.fd);
            LOG_INFO("File lock released on %s during cleanup", pair.first.c_str());
        }
    }
    
    locks_.clear();
}

bool FileLockManager::acquire_lock(const std::string& file_path, FileLockType lock_type) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    // 检查路径是否已锁定
    auto it = locks_.find(file_path);
    if (it != locks_.end()) {
        // 如果已经有锁，检查是否可以共享
        if (it->second.lock_type == FileLockType::EXCLUSIVE || 
            (it->second.lock_type == FileLockType::SHARED && lock_type == FileLockType::EXCLUSIVE)) {
            LOG_WARNING("File %s already locked with incompatible lock type", file_path.c_str());
            return false;
        }
        
        // 如果都是共享锁，返回成功
        if (it->second.lock_type == FileLockType::SHARED && lock_type == FileLockType::SHARED) {
            LOG_DEBUG("File %s already has shared lock, reusing", file_path.c_str());
            return true;
        }
    }
    
    // 确保目录存在
    fs::path path(file_path);
    try {
        if (!path.parent_path().empty() && !fs::exists(path.parent_path())) {
            fs::create_directories(path.parent_path());
        }
    } catch (const std::exception& e) {
        LOG_ERROR("Failed to create directory for %s: %s", file_path.c_str(), e.what());
        return false;
    }
    
    // 如果文件不存在且请求的是独占锁，创建一个占位文件
    bool need_create = false;
    if (!fs::exists(file_path) && lock_type == FileLockType::EXCLUSIVE) {
        need_create = true;
    }
    
    // 打开或创建文件
    int flags = O_RDWR;
    if (need_create) {
        flags |= O_CREAT;
    }
    
    int fd = open(file_path.c_str(), flags, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);
    if (fd < 0) {
        LOG_ERROR("Failed to open file for locking: %s, error: %s", 
                  file_path.c_str(), strerror(errno));
        return false;
    }
    
    // 根据锁类型选择flock操作
    int operation = (lock_type == FileLockType::EXCLUSIVE) ? LOCK_EX : LOCK_SH;
    
    // 非阻塞方式尝试获取锁，失败后进行重试
    operation |= LOCK_NB; // 添加非阻塞标志
    
    const int max_retries = 5;
    int retry_count = 0;
    bool success = false;
    
    while (retry_count < max_retries) {
        if (flock(fd, operation) == 0) {
            success = true;
            break;
        }
        
        // 如果错误是由于文件已被锁定，则等待后重试
        if (errno == EWOULDBLOCK) {
            LOG_WARNING("File %s is locked by another process, retrying (%d/%d)...", 
                        file_path.c_str(), retry_count + 1, max_retries);
            retry_count++;
            std::this_thread::sleep_for(std::chrono::milliseconds(200 * retry_count)); // 递增重试间隔
            continue;
        }
        
        // 其他错误则直接返回失败
        LOG_ERROR("Failed to lock file %s: %s", file_path.c_str(), strerror(errno));
        close(fd);
        return false;
    }
    
    if (!success) {
        LOG_ERROR("Failed to lock file %s after %d retries", file_path.c_str(), max_retries);
        close(fd);
        return false;
    }
    
    // 添加到锁映射表中
    locks_[file_path] = FileLockInfo(fd, lock_type);
    
    LOG_INFO("Acquired %s lock on file %s", 
             (lock_type == FileLockType::EXCLUSIVE) ? "exclusive" : "shared", 
             file_path.c_str());
    
    return true;
}

bool FileLockManager::release_lock(const std::string& file_path) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    auto it = locks_.find(file_path);
    if (it == locks_.end()) {
        LOG_WARNING("Trying to release a lock that doesn't exist: %s", file_path.c_str());
        return false;
    }
    
    int fd = it->second.fd;
    if (fd >= 0) {
        // 释放锁并关闭文件
        if (flock(fd, LOCK_UN) != 0) {
            LOG_ERROR("Failed to unlock file %s: %s", file_path.c_str(), strerror(errno));
            return false;
        }
        
        close(fd);
        LOG_INFO("Released lock on file %s", file_path.c_str());
    }
    
    locks_.erase(it);
    return true;
}

bool FileLockManager::is_locked(const std::string& file_path) {
    std::lock_guard<std::mutex> lock(mutex_);
    return locks_.find(file_path) != locks_.end();
}

} // namespace server
} // namespace ft 