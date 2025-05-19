#include "file_handler.h"
#include "../../common/utils/logging/logger.h"
#include <filesystem>
#include <fstream>
#include <sstream>
#include <chrono>
#include <random>
#include <unistd.h>

namespace fs = std::filesystem;

namespace ft {
namespace server {

FileHandler::FileHandler(const std::string& storage_path)
    : storage_path_(storage_path) {
    
    // 确保存储目录存在
    try {
        if (!fs::exists(storage_path_)) {
            fs::create_directories(storage_path_);
        }
    } catch (const std::exception& e) {
        LOG_ERROR("Failed to create storage directory: %s", e.what());
    }
}

FileHandler::~FileHandler() {
}

FileOperationResult FileHandler::handle_upload(const protocol::UploadMessage& upload_msg) {
    FileOperationResult result;
    
    try {
        // 获取文件信息
        std::string filename = upload_msg.get_filename();
        uint64_t offset = upload_msg.get_offset();
        uint64_t total_size = upload_msg.get_total_size();
        bool is_last_chunk = upload_msg.is_last_chunk();
        
        LOG_INFO("Handling upload request for file %s, offset: %llu, chunk size: %zu, total size: %llu, last chunk: %d",
                 filename.c_str(), offset, upload_msg.get_file_data().size(), total_size, is_last_chunk);
        
        // 获取文件完整路径
        std::string file_path = get_full_path(filename);
        
        // 确保目录存在
        fs::path path(file_path);
        if (!path.parent_path().empty()) {
            fs::create_directories(path.parent_path());
        }
        
        // 获取文件锁 (上传需要独占锁)
        FileLockManager& lock_manager = FileLockManager::instance();
        if (!lock_manager.acquire_lock(file_path, FileLockType::EXCLUSIVE)) {
            result.error_message = "Failed to acquire exclusive lock for file: " + filename;
            LOG_ERROR("%s, possibly locked by another user", result.error_message.c_str());
            return result;
        }
        
        // 创建版本记录 (仅当是第一个块并且文件已存在时)
        if (offset == 0 && fs::exists(file_path)) {
            FileVersionManager::instance().create_version(file_path);
            LOG_INFO("Created version backup for file before overwrite: %s", filename.c_str());
        }
        
        // 安全写入文件数据
        const std::vector<uint8_t>& file_data = upload_msg.get_file_data();
        result = safe_write_file(file_path, file_data.data(), file_data.size(), offset);
        
        // 如果是最后一块，清理旧版本
        if (is_last_chunk && result.success) {
            FileVersionManager::instance().cleanup_old_versions(file_path);
        }
        
        // 释放文件锁
        lock_manager.release_lock(file_path);
        
    } catch (const std::exception& e) {
        result.error_message = "Exception while handling upload: " + std::string(e.what());
        LOG_ERROR("%s", result.error_message.c_str());
        
        // 确保锁被释放
        FileLockManager::instance().release_lock(get_full_path(upload_msg.get_filename()));
    }
    
    return result;
}

FileOperationResult FileHandler::handle_download(const protocol::DownloadMessage& download_msg,
                                              std::function<void(const void*, size_t, bool)> callback) {
    FileOperationResult result;
    
    try {
        // 获取文件信息
        std::string filename = download_msg.get_filename();
        uint64_t offset = download_msg.get_offset();
        uint64_t length = download_msg.get_length();
        
        LOG_INFO("Handling download request for file %s, offset: %llu, length: %llu",
                 filename.c_str(), offset, length);
        
        // 获取文件完整路径
        std::string file_path = get_full_path(filename);
        
        // 检查文件是否存在
        if (!fs::exists(file_path)) {
            result.error_message = "File not found: " + filename;
            LOG_ERROR("%s", result.error_message.c_str());
            return result;
        }
        
        // 获取文件锁 (下载需要共享锁)
        FileLockManager& lock_manager = FileLockManager::instance();
        if (!lock_manager.acquire_lock(file_path, FileLockType::SHARED)) {
            result.error_message = "Failed to acquire shared lock for file: " + filename;
            LOG_ERROR("%s", result.error_message.c_str());
            return result;
        }
        
        // 获取文件大小
        uint64_t file_size = fs::file_size(file_path);
        
        // 检查偏移量是否有效
        if (offset >= file_size) {
            lock_manager.release_lock(file_path);
            result.error_message = "Invalid offset: " + std::to_string(offset);
            LOG_ERROR("%s", result.error_message.c_str());
            return result;
        }
        
        // 打开文件
        std::ifstream file(file_path, std::ios::binary);
        if (!file.is_open()) {
            lock_manager.release_lock(file_path);
            result.error_message = "Failed to open file for reading: " + file_path;
            LOG_ERROR("%s", result.error_message.c_str());
            return result;
        }
        
        // 设置读取位置
        file.seekg(offset);
        
        // 计算分块大小，默认使用1MB的块大小
        const size_t chunk_size = 1024 * 1024;
        
        // 如果指定了长度，则使用指定长度，否则从当前偏移量读取到文件末尾
        uint64_t remaining = (length > 0) ? length : (file_size - offset);
        uint64_t current_offset = offset;
        
        while (remaining > 0 && file.good()) {
            // 计算当前块大小
            size_t current_chunk_size = static_cast<size_t>(std::min(static_cast<uint64_t>(chunk_size), remaining));
            
            // 读取文件数据
            std::vector<uint8_t> file_data(current_chunk_size);
            file.read(reinterpret_cast<char*>(file_data.data()), current_chunk_size);
            
            // 实际读取的字节数
            size_t bytes_read = static_cast<size_t>(file.gcount());
            file_data.resize(bytes_read);
            
            // 判断是否为最后一个块
            bool is_last_chunk = (current_offset + bytes_read >= file_size) || (bytes_read < current_chunk_size);
            
            // 调用回调函数
            if (callback) {
                callback(file_data.data(), file_data.size(), is_last_chunk);
            }
            
            // 更新偏移量和剩余字节数
            current_offset += bytes_read;
            remaining -= bytes_read;
            result.bytes_processed += bytes_read;
            
            // 如果读取的数据小于请求的块大小，说明已经到达文件末尾
            if (bytes_read < current_chunk_size) {
                break;
            }
        }
        
        file.close();
        
        // 释放文件锁
        lock_manager.release_lock(file_path);
        
        // 设置结果
        result.success = true;
        
        LOG_INFO("Download completed for file %s, total sent: %llu bytes",
                 filename.c_str(), result.bytes_processed);
        
    } catch (const std::exception& e) {
        result.error_message = "Exception while handling download: " + std::string(e.what());
        LOG_ERROR("%s", result.error_message.c_str());
        
        // 确保锁被释放
        FileLockManager::instance().release_lock(get_full_path(download_msg.get_filename()));
    }
    
    return result;
}

bool FileHandler::file_exists(const std::string& filename) const {
    return fs::exists(get_full_path(filename));
}

uint64_t FileHandler::get_file_size(const std::string& filename) const {
    try {
        return fs::file_size(get_full_path(filename));
    } catch (const std::exception& e) {
        LOG_ERROR("Failed to get file size: %s", e.what());
        return 0;
    }
}

bool FileHandler::delete_file(const std::string& filename) {
    try {
        std::string file_path = get_full_path(filename);
        
        // 获取独占锁
        FileLockManager& lock_manager = FileLockManager::instance();
        if (!lock_manager.acquire_lock(file_path, FileLockType::EXCLUSIVE)) {
            LOG_ERROR("Failed to acquire lock for deletion: %s", filename.c_str());
            return false;
        }
        
        // 创建删除前的版本记录
        if (fs::exists(file_path)) {
            FileVersionManager::instance().create_version(file_path);
            LOG_INFO("Created version backup before deletion: %s", filename.c_str());
        }
        
        // 删除文件
        bool success = fs::remove(file_path);
        
        // 释放锁
        lock_manager.release_lock(file_path);
        
        return success;
    } catch (const std::exception& e) {
        LOG_ERROR("Failed to delete file: %s", e.what());
        
        // 确保锁被释放
        try {
            FileLockManager::instance().release_lock(get_full_path(filename));
        } catch (...) {
            // 忽略释放锁时的错误
        }
        
        return false;
    }
}

std::vector<FileVersionInfo> FileHandler::get_file_versions(const std::string& filename) {
    std::string file_path = get_full_path(filename);
    return FileVersionManager::instance().get_all_versions(file_path);
}

bool FileHandler::restore_file_version(const std::string& filename, size_t version) {
    std::string file_path = get_full_path(filename);
    
    // 获取独占锁
    FileLockManager& lock_manager = FileLockManager::instance();
    if (!lock_manager.acquire_lock(file_path, FileLockType::EXCLUSIVE)) {
        LOG_ERROR("Failed to acquire lock for version restore: %s", filename.c_str());
        return false;
    }
    
    // 恢复版本
    bool success = FileVersionManager::instance().restore_version(file_path, version);
    
    // 释放锁
    lock_manager.release_lock(file_path);
    
    return success;
}

std::string FileHandler::get_full_path(const std::string& filename) const {
    fs::path path(storage_path_);
    return (path / filename).string();
}

FileOperationResult FileHandler::safe_write_file(const std::string& file_path, 
                                               const void* data, 
                                               size_t size, 
                                               uint64_t offset) {
    FileOperationResult result;
    
    try {
        // 如果是第一个块，使用临时文件和原子操作
        if (offset == 0) {
            // 创建临时文件路径
            std::stringstream ss;
            ss << file_path << ".tmp." << getpid() << "." 
               << std::chrono::system_clock::now().time_since_epoch().count();
            std::string temp_path = ss.str();
            
            // 打开临时文件
            std::ofstream temp_file(temp_path, std::ios::binary | std::ios::trunc);
            if (!temp_file.is_open()) {
                result.error_message = "Failed to open temporary file: " + temp_path;
                LOG_ERROR("%s", result.error_message.c_str());
                return result;
            }
            
            // 写入数据
            if (size > 0) {
                temp_file.write(reinterpret_cast<const char*>(data), size);
                if (!temp_file) {
                    result.error_message = "Failed to write to temporary file";
                    LOG_ERROR("%s", result.error_message.c_str());
                    temp_file.close();
                    fs::remove(temp_path);  // 清理临时文件
                    return result;
                }
            }
            
            temp_file.close();
            
            // 原子替换原文件
            try {
                fs::rename(temp_path, file_path);
                LOG_INFO("Atomically replaced file: %s", file_path.c_str());
            } catch (const std::exception& e) {
                result.error_message = "Failed to rename temporary file: " + std::string(e.what());
                LOG_ERROR("%s", result.error_message.c_str());
                fs::remove(temp_path);  // 清理临时文件
                return result;
            }
        } else {
            // 追加写入模式
            std::fstream file(file_path, std::ios::binary | std::ios::in | std::ios::out);
            if (!file.is_open()) {
                result.error_message = "Failed to open file for appending: " + file_path;
                LOG_ERROR("%s", result.error_message.c_str());
                return result;
            }
            
            // 设置写入位置
            file.seekp(offset);
            
            // 写入数据
            if (size > 0) {
                file.write(reinterpret_cast<const char*>(data), size);
                if (!file) {
                    result.error_message = "Failed to append to file";
                    LOG_ERROR("%s", result.error_message.c_str());
                    file.close();
                    return result;
                }
            }
            
            file.close();
        }
        
        // 设置结果
        result.success = true;
        result.bytes_processed = size;
        
        LOG_INFO("Safe write operation completed for %s, offset: %llu, size: %zu", 
                file_path.c_str(), offset, size);
        
    } catch (const std::exception& e) {
        result.error_message = "Exception in safe_write_file: " + std::string(e.what());
        LOG_ERROR("%s", result.error_message.c_str());
    }
    
    return result;
}

} // namespace server
} // namespace ft 