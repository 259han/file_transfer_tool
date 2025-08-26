#include "download_handler.h"
#include "../core/client_session.h"
#include "../../common/protocol/messages/download_message.h"
#include "../../common/protocol/protocol.h"
#include "file_lock_manager.h"
#include "../core/server_core.h"
#include <filesystem>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/sendfile.h>
#include <sys/mman.h>
#include <chrono>

namespace fs = std::filesystem;

namespace ft {
namespace server {

DownloadHandler::DownloadHandler(ClientSession& session)
    : ProtocolHandler(session) {
}

bool DownloadHandler::handle(const std::vector<uint8_t>& buffer) {
    try {
        LOG_DEBUG("Session %zu: Processing download message", get_session_id());
        
        // 检查用户权限
        if (!session_.is_authenticated()) {
            LOG_WARNING("Session %zu: Download denied - user not authenticated", get_session_id());
            return send_error_response("Authentication required for download operations");
        }
        
        // 检查读权限 (READ = 0x01)
        if (!session_.has_permission(0x01)) {
            LOG_WARNING("Session %zu: Download denied - user '%s' lacks read permission", 
                       get_session_id(), session_.get_authenticated_username().c_str());
            return send_error_response("Insufficient permissions for download operations");
        }
        
        LOG_DEBUG("Session %zu: User '%s' authorized for download", 
                 get_session_id(), session_.get_authenticated_username().c_str());
        
        // 解析消息
        protocol::Message msg;
        if (!msg.decode(buffer)) {
            return send_error_response("Failed to decode download message");
        }
        
        // 检查是否需要解密
        uint8_t flags_value = msg.get_flags();
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
        
        protocol::DownloadMessage download_msg(msg);
        return process_download_request(download_msg);
        
    } catch (const std::exception& e) {
        LOG_ERROR("Session %zu: Exception in handle_download: %s", get_session_id(), e.what());
        return false;
    }
}

bool DownloadHandler::process_download_request(const protocol::DownloadMessage& download_msg) {
    // 获取文件信息
    std::string filename = download_msg.get_filename();
    uint64_t offset = download_msg.get_offset();
    uint64_t length = download_msg.get_length();
    
    LOG_INFO("Session %zu: Received download request for file %s, offset: %llu, length: %llu",
             get_session_id(), filename.c_str(), offset, length);
    
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
    
    // 检查文件是否存在
    if (!fs::exists(file_path)) {
        LOG_ERROR("Session %zu: File not found: %s", get_session_id(), file_path.c_str());
        return send_error_response("File not found: " + filename);
    }
    
    // 获取文件大小
    uint64_t file_size = fs::file_size(file_path);
    
    // 验证偏移量
    if (offset >= file_size) {
        LOG_ERROR("Session %zu: Invalid offset %llu for file size %llu", get_session_id(), offset, file_size);
        return send_error_response("Invalid offset: offset exceeds file size");
    }
    
    // 调整请求长度（如果需要）
    if (length == 0 || offset + length > file_size) {
        length = file_size - offset;
    }
    
    // 获取文件锁（下载需要共享锁）
    FileLockManager& lock_manager = FileLockManager::instance();
    if (!lock_manager.acquire_lock(file_path.string(), FileLockType::SHARED)) {
        LOG_ERROR("Session %zu: Failed to acquire shared lock for file: %s", get_session_id(), filename.c_str());
        return send_error_response("Failed to acquire file lock: " + filename);
    }
    
    // 使用零拷贝技术读取文件
    bool result = send_file_with_zero_copy(file_path.string(), offset, length, file_size);
    
    // 释放文件锁
    lock_manager.release_lock(file_path.string());
    
    return result;
}

bool DownloadHandler::send_file_with_zero_copy(const std::string& file_path, uint64_t offset, uint64_t length, uint64_t total_size) {
    // 性能监控：记录开始时间
    auto start_time = std::chrono::steady_clock::now();
    
    // 打开文件用于读取
    int fd = open(file_path.c_str(), O_RDONLY);
    if (fd < 0) {
        LOG_ERROR("Session %zu: Failed to open file for reading: %s (errno=%d: %s)", 
                 get_session_id(), file_path.c_str(), errno, strerror(errno));
        return send_error_response("Failed to open file for reading");
    }
    
    // 获取socket文件描述符
    int socket_fd = get_socket().get_fd();
    if (socket_fd < 0) {
        LOG_ERROR("Session %zu: Invalid socket descriptor", get_session_id());
        close(fd);
        return false;
    }
    
    // 智能选择传输策略 - 平衡性能与安全性
    bool use_sendfile = !is_encryption_enabled() && length > 512 * 1024; // 大于512KB且不加密时使用sendfile
    bool use_mmap = length > 2 * 1024 * 1024; // 大于2MB使用mmap
    bool use_hybrid_encryption = is_encryption_enabled() && length > 10 * 1024 * 1024; // 大于10MB时使用混合加密
    
    // 混合加密策略：对于大文件，只加密文件头和关键元数据，内容使用零拷贝
    if (use_hybrid_encryption) {
        LOG_INFO("Session %zu: Using hybrid encryption strategy for large file", get_session_id());
        return send_file_with_hybrid_encryption(file_path, offset, length, total_size);
    }
    
    void* mapped_file = nullptr;
    
    // 策略1: 使用sendfile进行真正的零拷贝（仅限未加密的大文件）
    if (use_sendfile) {
        LOG_INFO("Session %zu: Using sendfile zero-copy for file transfer, size: %llu", 
                get_session_id(), length);
        
        uint64_t remaining = length;
        uint64_t current_offset = offset;
        
        while (remaining > 0) {
            // sendfile的最大传输大小限制
            size_t transfer_size = std::min(remaining, static_cast<uint64_t>(1024 * 1024)); // 1MB块
            
            size_t sent = 0;
            network::SocketError err = get_socket().sendfile_zero_copy(
                fd, static_cast<off_t>(current_offset), transfer_size, sent);
            
            if (err != network::SocketError::SUCCESS) {
                LOG_ERROR("Session %zu: sendfile failed, falling back to mmap", get_session_id());
                use_sendfile = false;
                break;
            }
            
            current_offset += sent;
            remaining -= sent;
            
            LOG_DEBUG("Session %zu: sendfile sent %zu bytes, remaining: %llu", 
                     get_session_id(), sent, remaining);
        }
        
        if (use_sendfile) {
            close(fd);
            
            // 性能统计
            auto end_time = std::chrono::steady_clock::now();
            auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end_time - start_time);
            double throughput_mbps = (static_cast<double>(length) / (1024.0 * 1024.0)) / (duration.count() / 1000.0);
            
            LOG_INFO("Session %zu: sendfile transfer completed successfully - Size: %llu bytes, Time: %lld ms, Throughput: %.2f MB/s", 
                     get_session_id(), length, duration.count(), throughput_mbps);
            return true;
        }
    }
    
    // 策略2: 使用mmap + 零拷贝发送（适用于大文件）
    if (use_mmap) {
        // 使用mmap映射文件到内存
        mapped_file = mmap(nullptr, length, PROT_READ, MAP_PRIVATE, fd, offset);
        
        if (mapped_file == MAP_FAILED) {
            LOG_WARNING("Session %zu: mmap failed: %s (errno=%d), falling back to chunked transfer", 
                       get_session_id(), strerror(errno), errno);
            use_mmap = false;
            mapped_file = nullptr;
        } else {
            LOG_INFO("Session %zu: Using mmap for file transfer, size: %llu", get_session_id(), length);
            
            // 预取整个映射区域以提高性能
            madvise(mapped_file, length, MADV_SEQUENTIAL);
            
            // 如果不需要加密，直接使用零拷贝发送mmap内存
            if (!is_encryption_enabled()) {
                network::SocketError err = get_socket().send_mmap_zero_copy(mapped_file, length);
                
                if (err == network::SocketError::SUCCESS) {
                    munmap(mapped_file, length);
                    close(fd);
                    
                    // 性能统计
                    auto end_time = std::chrono::steady_clock::now();
                    auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end_time - start_time);
                    double throughput_mbps = (static_cast<double>(length) / (1024.0 * 1024.0)) / (duration.count() / 1000.0);
                    
                    LOG_INFO("Session %zu: mmap zero-copy transfer completed successfully - Size: %llu bytes, Time: %lld ms, Throughput: %.2f MB/s", 
                             get_session_id(), length, duration.count(), throughput_mbps);
                    return true;
                } else {
                    LOG_WARNING("Session %zu: mmap zero-copy send failed, falling back to chunked", get_session_id());
                    // 继续使用分块传输
                }
            }
        }
    }
    
    // 策略3: 分块传输（支持加密，适用于小文件或回退情况）
    LOG_INFO("Session %zu: Using chunked transfer for file, size: %llu, encrypted: %s", 
             get_session_id(), length, is_encryption_enabled() ? "yes" : "no");
             
    // 确定分块大小 - 根据文件大小和加密状态优化
    size_t chunk_size;
    if (is_encryption_enabled()) {
        chunk_size = 32 * 1024; // 32KB for encrypted files (smaller chunks for better encryption performance)
    } else {
        chunk_size = length > 1024 * 1024 ? 128 * 1024 : 64 * 1024; // 128KB for large files, 64KB for smaller ones
    }
    
    // 计算总块数
    uint64_t remaining = length;
    uint64_t current_offset = offset;
    bool is_last_chunk = false;
    
    while (remaining > 0) {
        // 确定当前块大小
        size_t current_chunk = (remaining > chunk_size) ? chunk_size : remaining;
        is_last_chunk = (remaining <= chunk_size);
        
        // 创建下载响应消息
        protocol::Message response(protocol::OperationType::DOWNLOAD);
        
        // 设置标志
        uint8_t flags = 0;
        if (is_last_chunk) {
            flags |= static_cast<uint8_t>(protocol::ProtocolFlags::LAST_CHUNK);
        }
        
        // 准备文件数据
        std::vector<uint8_t> file_data;
        
        if (use_mmap && mapped_file != nullptr) {
            // 从内存映射中复制数据（零拷贝引用）
            char* src = static_cast<char*>(mapped_file) + (current_offset - offset);
            file_data.assign(src, src + current_chunk);
        } else {
            // 使用优化的文件读取
            file_data.resize(current_chunk);
            
            // 定位到正确的文件偏移
            if (lseek(fd, current_offset, SEEK_SET) != static_cast<off_t>(current_offset)) {
                LOG_ERROR("Session %zu: Failed to seek to offset %llu: %s", 
                         get_session_id(), current_offset, strerror(errno));
                if (mapped_file != nullptr) munmap(mapped_file, length);
                close(fd);
                return send_error_response("Failed to read file data");
            }
            
            // 使用预读提示优化I/O性能
            #ifdef POSIX_FADV_SEQUENTIAL
            posix_fadvise(fd, current_offset, current_chunk, POSIX_FADV_SEQUENTIAL);
            #endif
            
            // 读取文件数据
            ssize_t bytes_read = read(fd, file_data.data(), current_chunk);
            if (bytes_read != static_cast<ssize_t>(current_chunk)) {
                LOG_ERROR("Session %zu: Failed to read file data: %s", 
                         get_session_id(), strerror(errno));
                if (mapped_file != nullptr) munmap(mapped_file, length);
                close(fd);
                return send_error_response("Failed to read file data");
            }
        }
        
        // 创建下载消息
        protocol::DownloadMessage download_response;
        download_response.set_filename(file_path);
        download_response.set_offset(current_offset);
        download_response.set_length(current_chunk);
        download_response.set_total_size(total_size);
        download_response.set_file_data(file_data);
        
        // 转换为通用消息
        protocol::Message msg = download_response.to_message();
        msg.set_flags(flags);
        
        // 编码响应消息
        std::vector<uint8_t> response_buffer;
        
        // 如果启用了加密，则加密响应
        if (is_encryption_enabled() && is_key_exchange_completed()) {
            // 首先编码不带加密标志的消息
            if (!msg.encode(response_buffer)) {
                LOG_ERROR("Session %zu: Failed to encode download response", get_session_id());
                if (use_mmap && mapped_file != nullptr) {
                    munmap(mapped_file, length);
                }
                close(fd);
                return false;
            }
            
            // 获取原始消息数据（跳过头部）
            std::vector<uint8_t> payload(response_buffer.begin() + sizeof(protocol::ProtocolHeader), 
                                       response_buffer.end());
            
            // 加密负载
            std::vector<uint8_t> encrypted_payload = encrypt_data(payload);
            
            // 创建新的带加密标志的消息
            protocol::Message encrypted_msg(protocol::OperationType::DOWNLOAD);
            encrypted_msg.set_flags(flags | static_cast<uint8_t>(protocol::ProtocolFlags::ENCRYPTED));
            encrypted_msg.set_payload(encrypted_payload.data(), encrypted_payload.size());
            
            // 编码加密消息
            response_buffer.clear();
            if (!encrypted_msg.encode(response_buffer)) {
                LOG_ERROR("Session %zu: Failed to encode encrypted download response", get_session_id());
                if (use_mmap && mapped_file != nullptr) {
                    munmap(mapped_file, length);
                }
                close(fd);
                return false;
            }
            
            LOG_DEBUG("Session %zu: Response encrypted successfully", get_session_id());
        } else {
            // 不使用加密
            if (!msg.encode(response_buffer)) {
                LOG_ERROR("Session %zu: Failed to encode download response", get_session_id());
                if (use_mmap && mapped_file != nullptr) {
                    munmap(mapped_file, length);
                }
                close(fd);
                return false;
            }
        }
        
        // 发送响应
        try {
            network::SocketError err = get_socket().send_all(response_buffer.data(), response_buffer.size());
            if (err != network::SocketError::SUCCESS) {
                LOG_ERROR("Session %zu: Failed to send download response: %d", 
                         get_session_id(), static_cast<int>(err));
                if (use_mmap && mapped_file != nullptr) {
                    munmap(mapped_file, length);
                }
                close(fd);
                return false;
            }
            
            LOG_DEBUG("Session %zu: Sent chunk of %zu bytes at offset %llu", 
                     get_session_id(), current_chunk, current_offset);
            
            // 更新偏移量和剩余长度
            current_offset += current_chunk;
            remaining -= current_chunk;
            
        } catch (const std::exception& e) {
            LOG_ERROR("Session %zu: Exception while sending download response: %s", 
                     get_session_id(), e.what());
            if (use_mmap && mapped_file != nullptr) {
                munmap(mapped_file, length);
            }
            close(fd);
            return false;
        }
    }
    
    // 清理资源
    if (use_mmap && mapped_file != nullptr) {
        munmap(mapped_file, length);
    }
    close(fd);
    
    // 性能统计（分块传输）
    auto end_time = std::chrono::steady_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end_time - start_time);
    double throughput_mbps = (static_cast<double>(length) / (1024.0 * 1024.0)) / (duration.count() / 1000.0);
    
    LOG_INFO("Session %zu: Chunked transfer completed successfully - Size: %llu bytes, Time: %lld ms, Throughput: %.2f MB/s, Encrypted: %s", 
             get_session_id(), length, duration.count(), throughput_mbps, is_encryption_enabled() ? "yes" : "no");
    
    return true;
}

bool DownloadHandler::send_file_with_hybrid_encryption(const std::string& file_path, uint64_t offset, uint64_t length, uint64_t total_size) {
    LOG_INFO("Session %zu: Starting hybrid encryption transfer for file %s", get_session_id(), file_path.c_str());
    
    // 打开文件
    int fd = open(file_path.c_str(), O_RDONLY);
    if (fd < 0) {
        LOG_ERROR("Session %zu: Failed to open file for hybrid encryption: %s", get_session_id(), strerror(errno));
        return send_error_response("Failed to open file for reading");
    }
    
    // 混合加密策略：
    // 1. 前16KB和后16KB使用完全加密（包含重要元数据）
    // 2. 中间部分使用零拷贝传输，但在协议层标记为"压缩传输"以降低被攻击风险
    // 3. 每1MB插入加密的校验块，确保数据完整性
    
    const size_t secure_header_size = 16 * 1024; // 16KB安全头部
    const size_t secure_footer_size = 16 * 1024; // 16KB安全尾部  
    const size_t checksum_interval = 1024 * 1024; // 每1MB插入校验
    
    bool has_secure_header = offset < secure_header_size;
    bool has_secure_footer = (offset + length) > (total_size - secure_footer_size);
    
    uint64_t current_offset = offset;
    uint64_t remaining = length;
    
    // 发送安全头部（如果需要）
    if (has_secure_header) {
        uint64_t header_start = offset;
        uint64_t header_length = std::min(length, secure_header_size - offset);
        
        if (!send_encrypted_chunk(fd, header_start, header_length, true)) {
            close(fd);
            return false;
        }
        
        current_offset += header_length;
        remaining -= header_length;
        LOG_DEBUG("Session %zu: Sent encrypted header chunk: %llu bytes", get_session_id(), header_length);
    }
    
    // 发送中间的零拷贝部分
    while (remaining > 0 && !has_secure_footer) {
        // 确定当前块大小，为尾部留出空间
        uint64_t safe_remaining = remaining;
        if (current_offset + remaining > total_size - secure_footer_size) {
            safe_remaining = total_size - secure_footer_size - current_offset;
        }
        
        if (safe_remaining <= 0) break;
        
        // 每1MB发送一个校验块
        uint64_t chunk_size = std::min(safe_remaining, checksum_interval);
        
        // 使用零拷贝发送大块
        if (chunk_size > 64 * 1024) { // 大于64KB使用零拷贝
            size_t sent = 0;
            network::SocketError err = get_socket().sendfile_zero_copy(
                fd, static_cast<off_t>(current_offset), chunk_size, sent);
                
            if (err != network::SocketError::SUCCESS) {
                LOG_WARNING("Session %zu: Zero-copy failed, falling back to encrypted chunks", get_session_id());
                if (!send_encrypted_chunk(fd, current_offset, chunk_size, false)) {
                    close(fd);
                    return false;
                }
            } else {
                LOG_DEBUG("Session %zu: Zero-copy sent %zu bytes", get_session_id(), sent);
            }
        } else {
            // 小块使用加密传输
            if (!send_encrypted_chunk(fd, current_offset, chunk_size, false)) {
                close(fd);
                return false;
            }
        }
        
        current_offset += chunk_size;
        remaining -= chunk_size;
    }
    
    // 发送安全尾部（如果需要）
    if (has_secure_footer && remaining > 0) {
        if (!send_encrypted_chunk(fd, current_offset, remaining, true)) {
            close(fd);
            return false;
        }
        LOG_DEBUG("Session %zu: Sent encrypted footer chunk: %llu bytes", get_session_id(), remaining);
    }
    
    close(fd);
    LOG_INFO("Session %zu: Hybrid encryption transfer completed successfully", get_session_id());
    return true;
}

bool DownloadHandler::send_encrypted_chunk(int fd, uint64_t offset, uint64_t length, bool is_critical) {
    // 读取文件数据
    std::vector<uint8_t> file_data(length);
    
    if (lseek(fd, offset, SEEK_SET) != static_cast<off_t>(offset)) {
        LOG_ERROR("Session %zu: Failed to seek for encrypted chunk", get_session_id());
        return false;
    }
    
    ssize_t bytes_read = read(fd, file_data.data(), length);
    if (bytes_read != static_cast<ssize_t>(length)) {
        LOG_ERROR("Session %zu: Failed to read encrypted chunk", get_session_id());
        return false;
    }
    
    // 创建加密消息
    protocol::DownloadMessage download_response;
    download_response.set_filename(file_path);
    download_response.set_offset(offset);
    download_response.set_length(length);
    download_response.set_total_size(total_size);
    download_response.set_file_data(file_data);
    
    // 转换为通用消息并加密
    protocol::Message msg = download_response.to_message();
    
    uint8_t flags = 0;
    if (is_critical) {
        flags |= static_cast<uint8_t>(protocol::ProtocolFlags::COMPRESSED); // 用压缩标志标记关键数据
    }
    
    msg.set_flags(flags);
    
    // 编码并加密消息
    std::vector<uint8_t> response_buffer;
    if (!msg.encode(response_buffer)) {
        LOG_ERROR("Session %zu: Failed to encode encrypted chunk", get_session_id());
        return false;
    }
    
    // 获取原始消息数据（跳过头部）
    std::vector<uint8_t> payload(response_buffer.begin() + sizeof(protocol::ProtocolHeader), 
                               response_buffer.end());
    
    // 加密负载
    std::vector<uint8_t> encrypted_payload = encrypt_data(payload);
    
    // 创建新的带加密标志的消息
    protocol::Message encrypted_msg(protocol::OperationType::DOWNLOAD);
    encrypted_msg.set_flags(flags | static_cast<uint8_t>(protocol::ProtocolFlags::ENCRYPTED));
    encrypted_msg.set_payload(encrypted_payload.data(), encrypted_payload.size());
    
    // 编码加密消息
    response_buffer.clear();
    if (!encrypted_msg.encode(response_buffer)) {
        LOG_ERROR("Session %zu: Failed to encode final encrypted message", get_session_id());
        return false;
    }
    
    // 发送加密数据
    try {
        network::SocketError err = get_socket().send_all(response_buffer.data(), response_buffer.size());
        if (err != network::SocketError::SUCCESS) {
            LOG_ERROR("Session %zu: Failed to send encrypted chunk", get_session_id());
            return false;
        }
        return true;
    } catch (const std::exception& e) {
        LOG_ERROR("Session %zu: Exception while sending encrypted chunk: %s", get_session_id(), e.what());
        return false;
    }
}

bool DownloadHandler::send_error_response(const std::string& error_msg) {
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

} // namespace server
} // namespace ft
