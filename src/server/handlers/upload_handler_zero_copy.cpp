#include "upload_handler.h"
#include "../core/client_session.h"
#include "../../common/protocol/messages/upload_message.h"
#include "../../common/protocol/protocol.h"
#include "file_lock_manager.h"
#include "file_version.h"
#include "../core/server_core.h"
#include <filesystem>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/sendfile.h>
#include <sys/mman.h>
#include <chrono>
#ifdef __linux__
#include <linux/falloc.h>
#endif

namespace fs = std::filesystem;

namespace ft {
namespace server {

UploadHandler::UploadHandler(ClientSession& session)
    : ProtocolHandler(session) {
}

bool UploadHandler::handle(const std::vector<uint8_t>& buffer) {
    try {
        LOG_DEBUG("Session %zu: Processing upload message", get_session_id());
        
        // 检查用户权限
        if (!session_.is_authenticated()) {
            LOG_WARNING("Session %zu: Upload denied - user not authenticated", get_session_id());
            return send_error_response("Authentication required for upload operations");
        }
        
        // 检查写权限 (WRITE = 0x02)
        if (!session_.has_permission(0x02)) {
            LOG_WARNING("Session %zu: Upload denied - user '%s' lacks write permission", 
                       get_session_id(), session_.get_authenticated_username().c_str());
            return send_error_response("Insufficient permissions for upload operations");
        }
        
        LOG_DEBUG("Session %zu: User '%s' authorized for upload", 
                 get_session_id(), session_.get_authenticated_username().c_str());
        
        // 解析消息
        protocol::Message msg;
        if (!msg.decode(buffer)) {
            return send_error_response("Failed to decode upload message");
        }
        
        // 打印收到的消息信息
        uint8_t type_value = static_cast<uint8_t>(msg.get_operation_type());
        uint8_t flags_value = msg.get_flags();
        LOG_INFO("Session %zu: Decoded message - type: %d, flags: %d", 
                 get_session_id(), type_value, flags_value);
        
        // 检查是否需要解密
        bool is_encrypted = (flags_value & static_cast<uint8_t>(protocol::ProtocolFlags::ENCRYPTED)) != 0;
        
        if (is_encrypted && is_encryption_enabled() && is_key_exchange_completed()) {
            LOG_DEBUG("Session %zu: Message is encrypted, decrypting payload", get_session_id());
            
            // 获取负载并解密
            const std::vector<uint8_t>& encrypted_payload = msg.get_payload();
            std::vector<uint8_t> decrypted_payload = decrypt_data(encrypted_payload);
            
            // 更新消息的负载
            msg.set_payload(decrypted_payload.data(), decrypted_payload.size());
            
            // 清除加密标志
            msg.set_flags(flags_value & ~static_cast<uint8_t>(protocol::ProtocolFlags::ENCRYPTED));
            
            LOG_DEBUG("Session %zu: Payload decrypted successfully, size: %zu -> %zu", 
                      get_session_id(), encrypted_payload.size(), decrypted_payload.size());
        } else if (is_encrypted) {
            LOG_WARNING("Session %zu: Message is encrypted but encryption is not ready", get_session_id());
            return false;
        }
        
        protocol::UploadMessage upload_msg(msg);
        return process_upload_chunk(upload_msg);
        
    } catch (const std::exception& e) {
        LOG_ERROR("Session %zu: Exception in handle_upload: %s", get_session_id(), e.what());
        return false;
    }
}

bool UploadHandler::process_upload_chunk(const protocol::UploadMessage& upload_msg) {
    // 性能监控：记录开始时间
    auto start_time = std::chrono::steady_clock::now();
    
    // 获取文件信息
    std::string filename = upload_msg.get_filename();
    uint64_t offset = upload_msg.get_offset();
    uint64_t total_size = upload_msg.get_total_size();
    bool is_last_chunk = upload_msg.is_last_chunk();
    
    LOG_INFO("Session %zu: Received upload request for file %s, offset: %llu, chunk size: %zu, total size: %llu, last chunk: %d",
             get_session_id(), filename.c_str(), offset, upload_msg.get_file_data().size(), total_size, is_last_chunk);
    
    // 使用ServerCore中配置的存储路径
    fs::path storage_path = fs::path(ServerCore::get_storage_path());
    
    // 检查文件名是否已经包含存储路径前缀，避免路径重复
    fs::path file_path;
    if (filename.find(storage_path.string()) == 0) {
        file_path = filename;  // 如果已经包含存储路径，直接使用
    } else {
        file_path = storage_path / filename;  // 否则组合路径
    }
    
    LOG_INFO("Session %zu: Using storage path: %s, file path: %s", 
             get_session_id(), storage_path.c_str(), file_path.c_str());
    
    if (!fs::exists(storage_path)) {
        LOG_INFO("Session %zu: Creating storage directory: %s", get_session_id(), storage_path.c_str());
        fs::create_directories(storage_path);
    }
    
    // 获取文件锁（上传需要独占锁）
    FileLockManager& lock_manager = FileLockManager::instance();
    if (!lock_manager.acquire_lock(file_path.string(), FileLockType::EXCLUSIVE)) {
        LOG_ERROR("Session %zu: Failed to acquire exclusive lock for file: %s", get_session_id(), filename.c_str());
        return send_error_response("Failed to acquire file lock: " + filename);
    }
    
    // 如果是第一个块且文件已存在，创建版本备份
    if (offset == 0 && fs::exists(file_path)) {
        try {
            FileVersionManager::instance().create_version(file_path.string());
            LOG_INFO("Session %zu: Created version backup for file %s before overwrite", 
                    get_session_id(), filename.c_str());
        } catch (const std::exception& e) {
            LOG_WARNING("Session %zu: Failed to create version backup: %s", get_session_id(), e.what());
            // 继续处理，这不是致命错误
        }
    }
    
    // 智能选择文件打开策略
    int file_flags = O_WRONLY;
    if (offset == 0) {
        file_flags |= O_CREAT | O_TRUNC;
    }
    
    // 大文件使用直接I/O绕过缓存，小文件使用缓存I/O
    bool use_direct_io = total_size > 10 * 1024 * 1024; // 大于10MB使用直接I/O
    
    if (use_direct_io) {
        #ifdef O_DIRECT
        file_flags |= O_DIRECT;
        LOG_DEBUG("Session %zu: Using direct I/O for large file upload", get_session_id());
        #endif
    }
    
    // 添加异步I/O提示
    #ifdef O_DSYNC
    if (!use_direct_io) {
        file_flags |= O_DSYNC; // 确保数据同步写入
    }
    #endif
    
    mode_t mode = S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH; // 644权限
    int fd = open(file_path.c_str(), file_flags, mode);
    
    if (fd < 0) {
        LOG_ERROR("Session %zu: Failed to open file for writing: %s (errno=%d: %s)", 
                 get_session_id(), file_path.c_str(), errno, strerror(errno));
        lock_manager.release_lock(file_path.string());
        return send_error_response("Failed to open file for writing: " + filename);
    }
    
    // 如果不是第一个块，需要定位到正确的偏移位置
    if (offset > 0) {
        if (lseek(fd, offset, SEEK_SET) != static_cast<off_t>(offset)) {
            LOG_ERROR("Session %zu: Failed to seek to offset %llu: %s (errno=%d)", 
                     get_session_id(), offset, strerror(errno), errno);
            close(fd);
            lock_manager.release_lock(file_path.string());
            return send_error_response("Failed to seek to correct position in file: " + filename);
        }
    }
    
    // 获取文件数据
    const std::vector<uint8_t>& file_data = upload_msg.get_file_data();
    size_t data_size = file_data.size();
    
    if (data_size > 0) {
        ssize_t bytes_written = 0;
        
        if (use_direct_io) {
            // 对于直接I/O，确保内存对齐和大小对齐
            const size_t alignment = 512; // 典型的磁盘扇区大小
            size_t aligned_size = (data_size + alignment - 1) & ~(alignment - 1); // 向上对齐
            
            // 创建对齐的内存缓冲区
            void* aligned_buffer = nullptr;
            
            #ifdef _POSIX_C_SOURCE
            // 使用posix_memalign分配对齐内存
            if (posix_memalign(&aligned_buffer, alignment, aligned_size) != 0) {
                LOG_ERROR("Session %zu: Failed to allocate aligned memory: %s", 
                         get_session_id(), strerror(errno));
                close(fd);
                lock_manager.release_lock(file_path.string());
                return send_error_response("Failed to allocate memory for file write: " + filename);
            }
            
            // 复制数据到对齐的缓冲区，并用零填充
            memcpy(aligned_buffer, file_data.data(), data_size);
            if (aligned_size > data_size) {
                memset(static_cast<char*>(aligned_buffer) + data_size, 0, aligned_size - data_size);
            }
            
            // 写入文件
            bytes_written = write(fd, aligned_buffer, aligned_size);
            
            // 释放对齐内存
            free(aligned_buffer);
            
            // 调整返回值为实际数据大小
            if (bytes_written >= static_cast<ssize_t>(data_size)) {
                bytes_written = data_size;
            }
            
            LOG_DEBUG("Session %zu: Direct I/O write: requested=%zu, aligned=%zu, written=%zd", 
                     get_session_id(), data_size, aligned_size, bytes_written);
            #else
            // 如果不支持posix_memalign，回退到常规写入
            bytes_written = write(fd, file_data.data(), data_size);
            #endif
        } else {
            // 常规缓冲I/O，使用零拷贝优化的写入
            // 预分配磁盘空间以减少碎片
            if (offset == 0 && total_size > 0) {
                #ifdef FALLOC_FL_KEEP_SIZE
                fallocate(fd, 0, 0, total_size);
                #endif
            }
            
            // 批量写入优化
            const size_t batch_size = 256 * 1024; // 256KB批次
            size_t remaining = data_size;
            size_t written_total = 0;
            
            while (remaining > 0) {
                size_t current_batch = std::min(remaining, batch_size);
                
                ssize_t batch_written = write(fd, file_data.data() + written_total, current_batch);
                if (batch_written <= 0) {
                    LOG_ERROR("Session %zu: Batch write failed: %s", get_session_id(), strerror(errno));
                    break;
                }
                
                written_total += batch_written;
                remaining -= batch_written;
                
                // 如果未完全写入当前批次，重试
                if (batch_written < static_cast<ssize_t>(current_batch)) {
                    continue;
                }
            }
            
            bytes_written = written_total;
            LOG_DEBUG("Session %zu: Buffered I/O write: requested=%zu, written=%zd", 
                     get_session_id(), data_size, bytes_written);
        }
        
        if (bytes_written != static_cast<ssize_t>(data_size)) {
            LOG_ERROR("Session %zu: Failed to write file data: %s (errno=%d)", 
                     get_session_id(), strerror(errno), errno);
            close(fd);
            lock_manager.release_lock(file_path.string());
            return send_error_response("Failed to write file data: " + filename);
        }
        
        // 确保数据写入磁盘
        #ifdef HAVE_FDATASYNC
        fdatasync(fd);
        #else
        fsync(fd);
        #endif
        
        LOG_INFO("Session %zu: Successfully wrote %zu bytes at offset %llu", 
                get_session_id(), data_size, offset);
    }
    
    // 关闭文件
    close(fd);
    LOG_INFO("Session %zu: File closed successfully", get_session_id());
    
    // 发送响应
    if (!send_upload_response(is_last_chunk)) {
        lock_manager.release_lock(file_path.string());
        return false;
    }
    
    // 性能统计
    auto end_time = std::chrono::steady_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end_time - start_time);
    size_t chunk_size = upload_msg.get_file_data().size();
    double throughput_mbps = (static_cast<double>(chunk_size) / (1024.0 * 1024.0)) / (duration.count() / 1000.0);
    
    LOG_INFO("Session %zu: Upload chunk processed successfully for file %s - Chunk size: %zu bytes, Time: %lld ms, Throughput: %.2f MB/s, DirectIO: %s", 
             get_session_id(), filename.c_str(), chunk_size, duration.count(), throughput_mbps, use_direct_io ? "yes" : "no");

    // 如果是最后一块，清理旧版本
    if (is_last_chunk) {
        try {
            FileVersionManager::instance().cleanup_old_versions(file_path.string());
            LOG_INFO("Session %zu: Cleaned up old versions for file %s", get_session_id(), filename.c_str());
        } catch (const std::exception& e) {
            LOG_WARNING("Session %zu: Failed to cleanup old versions: %s", get_session_id(), e.what());
            // 不是致命错误，继续处理
        }
    }
    
    // 释放文件锁
    lock_manager.release_lock(file_path.string());
    return true;
}

bool UploadHandler::send_error_response(const std::string& error_msg) {
    protocol::Message error_response(protocol::OperationType::ERROR);
    error_response.set_payload(error_msg.data(), error_msg.size());
    
    std::vector<uint8_t> response_buffer;
    error_response.encode(response_buffer);
    
    try {
        get_socket().send_all(response_buffer.data(), response_buffer.size());
        return false; // 返回false表示处理失败
    } catch (const std::exception& e) {
        LOG_ERROR("Session %zu: Exception while sending error response: %s", get_session_id(), e.what());
        return false;
    }
}

bool UploadHandler::send_upload_response(bool is_last_chunk) {
    // 创建响应消息
    protocol::Message response_msg(protocol::OperationType::UPLOAD);
    
    // 设置最后一块标志
    uint8_t flags = 0;
    if (is_last_chunk) {
        flags |= static_cast<uint8_t>(protocol::ProtocolFlags::LAST_CHUNK);
    }
    response_msg.set_flags(flags);
    
    // 编码响应消息
    std::vector<uint8_t> response_buffer;
    
    // 如果启用了加密，则加密响应
    if (is_encryption_enabled() && is_key_exchange_completed()) {
        // 首先编码不带加密标志的消息
        if (!response_msg.encode(response_buffer)) {
            LOG_ERROR("Session %zu: Failed to encode upload response", get_session_id());
            return false;
        }
        
        // 获取原始消息数据（跳过头部）
        std::vector<uint8_t> payload(response_buffer.begin() + sizeof(protocol::ProtocolHeader), 
                                   response_buffer.end());
        
        // 加密负载
        std::vector<uint8_t> encrypted_payload = encrypt_data(payload);
        
        // 创建新的带加密标志的消息
        protocol::Message encrypted_msg(protocol::OperationType::UPLOAD);
        encrypted_msg.set_flags(static_cast<uint8_t>(protocol::ProtocolFlags::ENCRYPTED));
        encrypted_msg.set_payload(encrypted_payload.data(), encrypted_payload.size());
        
        // 编码加密消息
        response_buffer.clear();
        if (!encrypted_msg.encode(response_buffer)) {
            LOG_ERROR("Session %zu: Failed to encode encrypted upload response", get_session_id());
            return false;
        }
        
        LOG_DEBUG("Session %zu: Response encrypted successfully", get_session_id());
    } else {
        // 不使用加密
        if (!response_msg.encode(response_buffer)) {
            LOG_ERROR("Session %zu: Failed to encode upload response", get_session_id());
            return false;
        }
    }
    
    // 发送响应
    try {
        network::SocketError err = get_socket().send_all(response_buffer.data(), response_buffer.size());
        if (err != network::SocketError::SUCCESS) {
            LOG_ERROR("Session %zu: Failed to send upload response: %d", 
                     get_session_id(), static_cast<int>(err));
            return false;
        }
        
        LOG_DEBUG("Session %zu: Upload response sent successfully", get_session_id());
        return true;
    } catch (const std::exception& e) {
        LOG_ERROR("Session %zu: Exception while sending upload response: %s", 
                 get_session_id(), e.what());
        return false;
    }
}

} // namespace server
} // namespace ft
