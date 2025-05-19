#pragma once

#include <string>
#include <memory>
#include <functional>
#include <fstream>
#include "../../common/protocol/messages/upload_message.h"
#include "../../common/protocol/messages/download_message.h"
#include "file_lock_manager.h"
#include "file_version.h"

namespace ft {
namespace server {

/**
 * @brief 文件操作结果
 */
struct FileOperationResult {
    bool success;               // 是否成功
    std::string error_message;  // 错误信息
    uint64_t bytes_processed;   // 处理的字节数
    
    FileOperationResult()
        : success(false),
          error_message(""),
          bytes_processed(0) {
    }
};

/**
 * @brief 文件处理程序类
 */
class FileHandler {
public:
    /**
     * @brief 构造函数
     * @param storage_path 存储路径
     */
    explicit FileHandler(const std::string& storage_path);
    
    /**
     * @brief 析构函数
     */
    ~FileHandler();
    
    /**
     * @brief 处理上传请求
     * @param upload_msg 上传消息
     * @return 处理结果
     */
    FileOperationResult handle_upload(const protocol::UploadMessage& upload_msg);
    
    /**
     * @brief 处理下载请求
     * @param download_msg 下载消息
     * @param callback 数据回调函数
     * @return 处理结果
     */
    FileOperationResult handle_download(const protocol::DownloadMessage& download_msg,
                                      std::function<void(const void*, size_t, bool)> callback);
    
    /**
     * @brief 检查文件是否存在
     * @param filename 文件名
     * @return 是否存在
     */
    bool file_exists(const std::string& filename) const;
    
    /**
     * @brief 获取文件大小
     * @param filename 文件名
     * @return 文件大小
     */
    uint64_t get_file_size(const std::string& filename) const;
    
    /**
     * @brief 删除文件
     * @param filename 文件名
     * @return 是否删除成功
     */
    bool delete_file(const std::string& filename);
    
    /**
     * @brief 获取文件版本列表
     * @param filename 文件名
     * @return 版本列表
     */
    std::vector<FileVersionInfo> get_file_versions(const std::string& filename);
    
    /**
     * @brief 恢复文件到指定版本
     * @param filename 文件名
     * @param version 版本号
     * @return 是否恢复成功
     */
    bool restore_file_version(const std::string& filename, size_t version);
    
private:
    /**
     * @brief 获取文件完整路径
     * @param filename 文件名
     * @return 完整路径
     */
    std::string get_full_path(const std::string& filename) const;
    
    /**
     * @brief 安全写入文件（使用临时文件和原子重命名）
     * @param file_path 目标文件路径
     * @param data 文件数据
     * @param size 数据大小
     * @param offset 写入偏移量
     * @return 操作结果
     */
    FileOperationResult safe_write_file(const std::string& file_path, 
                                      const void* data, 
                                      size_t size, 
                                      uint64_t offset);

private:
    std::string storage_path_;  // 存储路径
};

} // namespace server
} // namespace ft 