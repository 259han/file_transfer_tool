#pragma once

#include <string>
#include <memory>
#include <functional>
#include <fstream>
#include "../../common/protocol/messages/upload_message.h"
#include "../../common/protocol/messages/download_message.h"

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
    
private:
    /**
     * @brief 获取文件的完整路径
     * @param filename 文件名
     * @return 完整路径
     */
    std::string get_full_path(const std::string& filename) const;
    
private:
    std::string storage_path_;
};

} // namespace server
} // namespace ft 