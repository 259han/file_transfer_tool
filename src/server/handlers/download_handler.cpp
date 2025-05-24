#include "download_handler.h"
#include "../core/client_session.h"
#include "../../common/protocol/messages/download_message.h"
#include "../../common/protocol/protocol.h"
#include "file_lock_manager.h"
#include "../core/server_core.h"
#include <filesystem>
#include <fstream>
#include <thread>

namespace fs = std::filesystem;

namespace ft {
namespace server {

DownloadHandler::DownloadHandler(ClientSession& session)
    : ProtocolHandler(session) {
}

bool DownloadHandler::handle(const std::vector<uint8_t>& buffer) {
    try {
        // 添加额外调试信息
        LOG_INFO("Session %zu: Received download message, buffer size: %zu", get_session_id(), buffer.size());
        
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
        
        // 解析下载消息
        protocol::Message msg;
        if (!msg.decode(buffer)) {
            LOG_ERROR("Session %zu: Failed to decode download message", get_session_id());
            return false;
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
        LOG_ERROR("Session %zu: Exception while handling download: %s", get_session_id(), e.what());
        
        // 错误发生，忽略文件锁清理中的异常
        // 由于在catch块中无法访问file_path变量，我们不进行锁的释放
        // FileLockManager在析构时会自动清理未释放的锁
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
        
        // 发送错误响应
        protocol::Message error_response(protocol::OperationType::ERROR);
        std::string error_msg = "File not found: " + filename;
        error_response.set_payload(error_msg.data(), error_msg.size());
        
        std::vector<uint8_t> response_buffer;
        error_response.encode(response_buffer);
        
        try {
            get_socket().send_all(response_buffer.data(), response_buffer.size());
            LOG_DEBUG("Session %zu: Sent error response: File not found", get_session_id());
        } catch (const std::exception& e) {
            LOG_ERROR("Session %zu: Exception while sending error response: %s", get_session_id(), e.what());
        }
        
        return false;
    }
    
    // 获取文件共享锁（读锁）
    FileLockManager& lock_manager = FileLockManager::instance();
    if (!lock_manager.acquire_lock(file_path.string(), FileLockType::SHARED)) {
        LOG_ERROR("Session %zu: Failed to acquire shared lock for file: %s", get_session_id(), filename.c_str());
        
        // 发送错误响应
        protocol::Message error_response(protocol::OperationType::ERROR);
        std::string error_msg = "Failed to acquire file lock: " + filename;
        error_response.set_payload(error_msg.data(), error_msg.size());
        
        std::vector<uint8_t> response_buffer;
        error_response.encode(response_buffer);
        
        get_socket().send_all(response_buffer.data(), response_buffer.size());
        return false;
    }
    
    // 发送文件数据
    bool result = send_file_data(file_path.string(), offset, length);
    
    // 释放文件锁
    lock_manager.release_lock(file_path.string());
    LOG_DEBUG("Session %zu: Released shared lock for file: %s", get_session_id(), filename.c_str());
    
    return result;
}

bool DownloadHandler::send_file_data(const std::string& file_path, uint64_t offset, uint64_t length) {
    // 获取文件大小
    uint64_t file_size = fs::file_size(file_path);
    LOG_DEBUG("Session %zu: File size: %llu bytes", get_session_id(), file_size);
    
    // 打开文件
    std::ifstream file(file_path, std::ios::binary);
    if (!file.is_open()) {
        LOG_ERROR("Session %zu: Failed to open file for reading: %s", get_session_id(), file_path.c_str());
        return false;
    }
    
    // 设置读取位置
    file.seekg(offset);
    LOG_DEBUG("Session %zu: Seeking to offset %llu", get_session_id(), offset);
    
    // 计算分块大小，默认使用1MB的块大小
    const size_t chunk_size = 1024 * 1024;
    LOG_DEBUG("Session %zu: Using chunk size: %zu bytes", get_session_id(), chunk_size);
    
    // 如果指定了长度，则使用指定长度，否则从当前偏移量读取到文件末尾
    uint64_t remaining = (length > 0) ? length : (file_size - offset);
    uint64_t current_offset = offset;
    
    LOG_DEBUG("Session %zu: Will transfer %llu bytes total", get_session_id(), remaining);
    
    // 单独处理空文件或读取长度为0的情况
    if (file_size == 0 || remaining == 0) {
        LOG_WARNING("Session %zu: File is empty or requested length is 0", get_session_id());
        
        // 创建下载响应消息，空数据
        protocol::DownloadMessage response_msg;
        response_msg.set_response_data(nullptr, 0, file_size, true);
        response_msg.set_offset(current_offset);
        
        // 编码消息
        std::vector<uint8_t> response_buffer;
        if (!response_msg.encode(response_buffer)) {
            LOG_ERROR("Session %zu: Failed to encode empty download response", get_session_id());
            return false;
        }
        
        // 发送响应
        LOG_DEBUG("Session %zu: Sending empty response with file_size=%llu", get_session_id(), file_size);
        network::SocketError err = get_socket().send_all(response_buffer.data(), response_buffer.size());
        if (err != network::SocketError::SUCCESS) {
            LOG_ERROR("Session %zu: Failed to send empty download response: %d", 
                      get_session_id(), static_cast<int>(err));
            return false;
        }
        
        LOG_INFO("Session %zu: Sent empty file response for file", get_session_id());
        file.close();
        return true;
    }
    
    size_t total_sent = 0;
    
    while (remaining > 0 && file.good()) {
        // 计算当前块大小
        size_t current_chunk_size = static_cast<size_t>(std::min(static_cast<uint64_t>(chunk_size), remaining));
        
        LOG_DEBUG("Session %zu: Reading chunk of size %zu at offset %llu", 
                  get_session_id(), current_chunk_size, current_offset);
        
        // 读取文件数据
        std::vector<uint8_t> file_data(current_chunk_size);
        file.read(reinterpret_cast<char*>(file_data.data()), current_chunk_size);
        
        // 实际读取的字节数
        size_t bytes_read = static_cast<size_t>(file.gcount());
        LOG_DEBUG("Session %zu: Actually read %zu bytes", get_session_id(), bytes_read);
        
        // 如果读取失败，退出循环
        if (bytes_read == 0 && !file.eof()) {
            LOG_ERROR("Session %zu: Failed to read file data at offset %llu", get_session_id(), current_offset);
            break;
        }
        
        // 调整数据大小为实际读取的大小
        file_data.resize(bytes_read);
        
        // 判断是否为最后一个块
        bool is_last_chunk = (current_offset + bytes_read >= file_size) || (bytes_read < current_chunk_size);
        
        // 显示前几个字节的内容以用于调试
        if (bytes_read > 0) {
            std::string data_preview;
            for (size_t i = 0; i < std::min(bytes_read, size_t(16)); ++i) {
                char hex[4];
                snprintf(hex, sizeof(hex), "%02x ", file_data[i]);
                data_preview += hex;
            }
            LOG_DEBUG("Session %zu: First bytes: %s", get_session_id(), data_preview.c_str());
        }
        
        // 发送数据块
        if (!send_data_chunk(file_data, current_offset, file_size, is_last_chunk)) {
            file.close();
            return false;
        }
        
        LOG_DEBUG("Session %zu: Sent chunk for file, offset: %llu, size: %zu, is_last: %d",
                  get_session_id(), current_offset, bytes_read, is_last_chunk);
        
        // 更新偏移量和剩余字节数
        current_offset += bytes_read;
        remaining -= bytes_read;
        total_sent += bytes_read;
        
        // 在返回客户端之前小暂停，给客户端处理数据的时间，根据数据大小动态调整延迟
        std::this_thread::sleep_for(std::chrono::milliseconds(bytes_read > 100000 ? 50 : 10));
        
        // 如果是最后一个块，退出循环
        if (is_last_chunk) {
            LOG_DEBUG("Session %zu: Last chunk sent, exiting download loop", get_session_id());
            break;
        }
        
        // 如果读取的数据小于请求的块大小，说明已经到达文件末尾
        if (bytes_read < current_chunk_size) {
            LOG_DEBUG("Session %zu: Reached end of file or read less than requested", get_session_id());
            break;
        }
    }
    
    file.close();
    
    LOG_INFO("Session %zu: Download completed for file, total sent: %zu bytes",
             get_session_id(), total_sent);
    
    return true;
}

bool DownloadHandler::send_data_chunk(const std::vector<uint8_t>& data, uint64_t offset, 
                                     uint64_t total_size, bool is_last_chunk) {
    // 创建下载响应消息
    protocol::DownloadMessage response_msg;
    response_msg.set_response_data(data.data(), data.size(), total_size, is_last_chunk);
    response_msg.set_offset(offset);
    
    LOG_DEBUG("Session %zu: Created download response with offset=%llu, size=%zu, total_size=%llu, is_last=%d",
              get_session_id(), offset, data.size(), total_size, is_last_chunk ? 1 : 0);

    // 编码消息
    std::vector<uint8_t> response_buffer;

    // 如果启用了加密，则加密响应
    if (is_encryption_enabled() && is_key_exchange_completed()) {
        // 首先编码不带加密标志的消息
        if (!response_msg.encode(response_buffer)) {
            LOG_ERROR("Session %zu: Failed to encode download response", get_session_id());
            return false;
        }
        
        // 获取原始消息数据（跳过头部）
        if (response_buffer.size() <= sizeof(protocol::ProtocolHeader)) {
            LOG_ERROR("Session %zu: Encoded response buffer too small", get_session_id());
            return false;
        }
        
        // 创建一个副本用于加密，避免直接修改response_buffer
        std::vector<uint8_t> payload_to_encrypt(response_buffer.begin() + sizeof(protocol::ProtocolHeader), 
                                              response_buffer.end());
        
        // 加密负载前记录一些调试信息
        if (payload_to_encrypt.size() > 0) {
            std::string data_preview;
            for (size_t i = 0; i < std::min(payload_to_encrypt.size(), size_t(16)); ++i) {
                char hex[4];
                snprintf(hex, sizeof(hex), "%02x ", payload_to_encrypt[i]);
                data_preview += hex;
            }
            LOG_DEBUG("Session %zu: Pre-encryption data preview: %s", get_session_id(), data_preview.c_str());
        }
        
        // 加密负载
        LOG_DEBUG("Session %zu: Encrypting download response payload of size %zu, offset=%llu, total_size=%llu", 
                 get_session_id(), payload_to_encrypt.size(), offset, total_size);
        std::vector<uint8_t> encrypted_payload = encrypt_data(payload_to_encrypt);
        
        // 检查加密是否成功
        if (encrypted_payload.empty() && !payload_to_encrypt.empty()) {
            LOG_ERROR("Session %zu: Encryption failed: input=%zu, output=0", 
                     get_session_id(), payload_to_encrypt.size());
            return false;
        }
        
        // 创建新的带加密标志的消息
        protocol::Message encrypted_msg(protocol::OperationType::DOWNLOAD);
        
        // 设置标志位：包括加密标志和最后一块标志（如果适用）
        uint8_t flags = static_cast<uint8_t>(protocol::ProtocolFlags::ENCRYPTED);
        if (is_last_chunk) {
            flags |= static_cast<uint8_t>(protocol::ProtocolFlags::LAST_CHUNK);
        }
        encrypted_msg.set_flags(flags);
        
        // 直接设置负载，避免再添加元数据
        encrypted_msg.set_payload(encrypted_payload.data(), encrypted_payload.size());
        
        // 加密后记录一些调试信息
        if (encrypted_payload.size() > 0) {
            std::string data_preview;
            for (size_t i = 0; i < std::min(encrypted_payload.size(), size_t(16)); ++i) {
                char hex[4];
                snprintf(hex, sizeof(hex), "%02x ", encrypted_payload[i]);
                data_preview += hex;
            }
            LOG_DEBUG("Session %zu: Post-encryption data preview: %s", get_session_id(), data_preview.c_str());
        }
        
        // 编码加密后的消息
        response_buffer.clear();
        if (!encrypted_msg.encode(response_buffer)) {
            LOG_ERROR("Session %zu: Failed to encode encrypted download response", get_session_id());
            return false;
        }
        
        LOG_DEBUG("Session %zu: Response encrypted successfully: buffer_size=%zu", 
                  get_session_id(), response_buffer.size());
    } else {
        // 不使用加密
        if (!response_msg.encode(response_buffer)) {
            LOG_ERROR("Session %zu: Failed to encode download response", get_session_id());
            return false;
        }
    }
    
    LOG_DEBUG("Session %zu: Sending response: data_size=%zu, buffer_size=%zu, is_last=%d, flags=%u", 
             get_session_id(), data.size(), response_buffer.size(), is_last_chunk ? 1 : 0,
             response_msg.get_flags());
    
    // 发送响应前检查连接状态
    if (!get_socket().is_connected()) {
        LOG_ERROR("Session %zu: Socket disconnected before sending response", get_session_id());
        return false;
    }
    
    // 发送响应，添加重试逻辑
    int send_retry = 0;
    const int max_send_retries = 3;
    network::SocketError err;
    bool send_success = false;
    
    while (send_retry < max_send_retries && !send_success) {
        // 每次发送前检查连接状态
        if (!get_socket().is_connected()) {
            LOG_ERROR("Session %zu: Socket disconnected during send retry %d", get_session_id(), send_retry + 1);
            break;
        }
        
        err = get_socket().send_all(response_buffer.data(), response_buffer.size());
        if (err == network::SocketError::SUCCESS) {
            send_success = true;
            LOG_DEBUG("Session %zu: Chunk sent successfully on try %d", get_session_id(), send_retry + 1);
        } else {
            send_retry++;
            
            // 对于客户端关闭连接的情况，使用较低的日志级别
            if (err == network::SocketError::CLOSED) {
                LOG_INFO("Session %zu: Client closed connection, stopping download", get_session_id());
                break;
            } else {
                LOG_WARNING("Session %zu: Failed to send download response on try %d: %d", 
                          get_session_id(), send_retry, static_cast<int>(err));
            }
            
            if (send_retry < max_send_retries) {
                // 短暂延迟后重试
                std::this_thread::sleep_for(std::chrono::milliseconds(50 * send_retry));
            }
        }
    }
    
    if (!send_success) {
        // 如果是客户端关闭连接导致的失败，这是正常情况，返回true
        if (err == network::SocketError::CLOSED) {
            LOG_DEBUG("Session %zu: Client closed connection during download, this is normal", get_session_id());
            return true;  // 返回true，避免上级报警告
        }
        
        LOG_ERROR("Session %zu: Failed to send download response after %d retries", 
                  get_session_id(), max_send_retries);
        return false;
    }
    
    return true;
}

} // namespace server
} // namespace ft 