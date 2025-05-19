#pragma once

#include <string>
#include <mutex>
#include <unordered_map>
#include <chrono>
#include <ctime>
#include <filesystem>
#include <vector>
#include <algorithm>
#include "../../common/utils/logging/logger.h"

namespace fs = std::filesystem;

namespace ft {
namespace server {

/**
 * @brief 文件版本信息
 */
struct FileVersionInfo {
    std::string filename;        // 原始文件名
    std::string versioned_name;  // 带版本号的文件名
    std::string timestamp;       // 版本时间戳
    size_t version;              // 版本号
    bool deleted;                // 是否已删除
    
    FileVersionInfo()
        : filename(""),
          versioned_name(""),
          timestamp(""),
          version(0),
          deleted(false) {
    }
    
    FileVersionInfo(const std::string& file, size_t ver)
        : filename(file),
          version(ver),
          deleted(false) {
        // 生成时间戳
        auto now = std::chrono::system_clock::now();
        auto now_time_t = std::chrono::system_clock::to_time_t(now);
        char time_buf[100];
        std::strftime(time_buf, sizeof(time_buf), "%Y%m%d_%H%M%S", std::localtime(&now_time_t));
        timestamp = time_buf;
        
        // 生成带版本的文件名
        // 示例: file.txt -> file_v1_20220101_120000.txt
        fs::path path(file);
        std::string stem = path.stem().string();
        std::string ext = path.extension().string();
        versioned_name = stem + "_v" + std::to_string(version) + "_" + timestamp + ext;
    }
};

/**
 * @brief 文件版本管理器
 * 
 * 管理文件的版本信息，支持文件版本跟踪和恢复
 */
class FileVersionManager {
public:
    /**
     * @brief 获取单例实例
     * @return 文件版本管理器实例
     */
    static FileVersionManager& instance();
    
    /**
     * @brief 创建新版本
     * @param file_path 文件路径
     * @return 带版本信息的文件路径
     */
    std::string create_version(const std::string& file_path);
    
    /**
     * @brief 获取最新版本
     * @param file_path 文件路径
     * @return 最新版本的文件信息
     */
    FileVersionInfo get_latest_version(const std::string& file_path);
    
    /**
     * @brief 获取所有版本
     * @param file_path 文件路径
     * @return 所有版本的列表
     */
    std::vector<FileVersionInfo> get_all_versions(const std::string& file_path);
    
    /**
     * @brief 恢复到指定版本
     * @param file_path 文件路径
     * @param version 版本号
     * @return 是否成功恢复
     */
    bool restore_version(const std::string& file_path, size_t version);
    
    /**
     * @brief 清理旧版本
     * @param file_path 文件路径
     * @param keep_count 保留版本数量
     */
    void cleanup_old_versions(const std::string& file_path, size_t keep_count = 5);
    
    /**
     * @brief 获取文件的真实路径
     * @param file_path 文件路径（原始路径或版本路径）
     * @return 真实存储的文件路径
     */
    std::string get_real_path(const std::string& file_path);

private:
    /**
     * @brief 构造函数
     */
    FileVersionManager();
    
    /**
     * @brief 析构函数
     */
    ~FileVersionManager();
    
    /**
     * @brief 加载文件的版本信息
     * @param file_path 文件路径
     */
    void load_versions(const std::string& file_path);
    
    /**
     * @brief 保存文件的版本信息
     * @param file_path 文件路径
     */
    void save_versions(const std::string& file_path);
    
    // 禁止拷贝和赋值
    FileVersionManager(const FileVersionManager&) = delete;
    FileVersionManager& operator=(const FileVersionManager&) = delete;

private:
    std::mutex mutex_;                                                    // 保护版本映射
    std::unordered_map<std::string, std::vector<FileVersionInfo>> versions_; // 文件版本映射表
    std::string version_dir_;                                            // 版本存储目录
};

} // namespace server
} // namespace ft 