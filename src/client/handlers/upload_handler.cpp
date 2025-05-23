#include "upload_handler.h"
#include "../../common/utils/logging/logger.h"
#include <fstream>
#include <filesystem>
#include <cmath>
#include <chrono>
#include <thread>
#include <cstring>

namespace fs = std::filesystem;

namespace ft {
namespace client {

UploadHandler::UploadHandler(const std::string& local_file,
                           const std::string& remote_file,
                           size_t chunk_size,
                           std::function<void(size_t, size_t)> progress_callback,
                           bool encryption_enabled,
                           const std::vector<uint8_t>& encryption_key,
                           const std::vector<uint8_t>& encryption_iv)
    : local_file_(local_file),
      remote_file_(remote_file),
      chunk_size_(chunk_size),
      progress_callback_(progress_callback),
      encryption_enabled_(encryption_enabled),
      encryption_key_(encryption_key),
      encryption_iv_(encryption_iv) {
    
    // 确保分块大小合理
    if (chunk_size_ == 0) {
        chunk_size_ = 1024 * 1024; // 默认分块大小为1MB
    }
}

UploadHandler::~UploadHandler() {
}

std::vector<uint8_t> UploadHandler::encrypt_data(const std::vector<uint8_t>& data) {
    if (!encryption_enabled_ || encryption_key_.empty() || encryption_iv_.empty()) {
        return data;
    }
    
    return ft::utils::Encryption::aes_encrypt(data, encryption_key_, encryption_iv_);
}

bool UploadHandler::upload(ft::network::TcpSocket& socket) {
    // 检查本地文件是否存在
    if (!fs::exists(local_file_)) {
        LOG_ERROR("Local file not found: %s", local_file_.c_str());
        return false;
    }
    
    // 获取文件大小
    size_t file_size = fs::file_size(local_file_);
    if (file_size == 0) {
        LOG_WARNING("File is empty: %s", local_file_.c_str());
    }
    
    LOG_INFO("Starting upload: %s -> %s (size: %zu bytes)",
             local_file_.c_str(), remote_file_.c_str(), file_size);
    
    // 打开文件
    std::ifstream file(local_file_, std::ios::binary);
    if (!file.is_open()) {
        LOG_ERROR("Failed to open file: %s", local_file_.c_str());
        return false;
    }
    
    // 计算分块数量
    size_t total_chunks = static_cast<size_t>(std::ceil(static_cast<double>(file_size) / chunk_size_));
    size_t uploaded_bytes = 0;
    bool success = true;
    
    // 分块上传
    for (size_t chunk_index = 0; chunk_index < total_chunks; ++chunk_index) {
        // 计算当前块的大小
        size_t current_offset = chunk_index * chunk_size_;
        size_t current_chunk_size = std::min(chunk_size_, file_size - current_offset);
        bool is_last_chunk = (chunk_index == total_chunks - 1);
        
        // 读取文件数据
        std::vector<uint8_t> buffer(current_chunk_size);
        file.seekg(current_offset);
        file.read(reinterpret_cast<char*>(buffer.data()), current_chunk_size);
        
        if (!file.good() && !is_last_chunk) {
            LOG_ERROR("Failed to read file data at offset %zu", current_offset);
            success = false;
            break;
        }
        
        // 创建上传消息
        protocol::UploadMessage upload_msg(remote_file_, current_offset, file_size, is_last_chunk);
        upload_msg.set_file_data(buffer.data(), buffer.size());
        
        // 编码消息
        std::vector<uint8_t> msg_buffer;
        
        // 如果启用了加密，设置加密标志并加密数据
        if (encryption_enabled_) {
            // 设置加密标志
            upload_msg.set_encrypted(true);
            
            // 编码原始消息
            if (!upload_msg.encode(msg_buffer)) {
                LOG_ERROR("Failed to encode upload message");
                success = false;
                break;
            }
            
            // 获取负载（跳过协议头）
            std::vector<uint8_t> payload(msg_buffer.begin() + sizeof(protocol::ProtocolHeader), 
                                       msg_buffer.end());
            
            // 加密负载
            std::vector<uint8_t> encrypted_payload = encrypt_data(payload);
            
            // 创建新的带加密标志的消息
            protocol::Message encrypted_msg(protocol::OperationType::UPLOAD);
            encrypted_msg.set_flags(static_cast<uint8_t>(protocol::ProtocolFlags::ENCRYPTED));
            encrypted_msg.set_payload(encrypted_payload.data(), encrypted_payload.size());
            
            // 编码加密消息
            msg_buffer.clear();
            if (!encrypted_msg.encode(msg_buffer)) {
                LOG_ERROR("Failed to encode encrypted upload message");
                success = false;
                break;
            }
            
            LOG_DEBUG("Upload message encrypted successfully");
        } else {
            // 不使用加密
            if (!upload_msg.encode(msg_buffer)) {
                LOG_ERROR("Failed to encode upload message");
                success = false;
                break;
            }
        }
        
        // 发送消息 - 添加重试机制
        LOG_INFO("Sending upload message, size: %zu bytes", msg_buffer.size());
        
        int send_retry_count = 0;
        const int max_send_retries = 3;
        bool send_success = false;
        
        while (send_retry_count < max_send_retries && !send_success) {
            network::SocketError err = socket.send_all(msg_buffer.data(), msg_buffer.size());
            if (err == network::SocketError::SUCCESS) {
                send_success = true;
            } else if (err == network::SocketError::TIMEOUT) {
                send_retry_count++;
                LOG_WARNING("Timeout while sending chunk, retry %d/%d", send_retry_count, max_send_retries);
                std::this_thread::sleep_for(std::chrono::milliseconds(100));
            } else {
                LOG_ERROR("Failed to send upload message: %d", static_cast<int>(err));
                success = false;
                break;
            }
        }
        
        if (!send_success) {
            LOG_ERROR("Failed to send upload message after retries");
            success = false;
            break;
        }
        
        // 接收响应
        std::vector<uint8_t> response_buffer(1024);
        size_t received = 0;
        network::SocketError err = socket.recv(response_buffer.data(), response_buffer.size(), received);
        if (err != network::SocketError::SUCCESS) {
            LOG_ERROR("Failed to receive response: %d", static_cast<int>(err));
            success = false;
            break;
        }
        
        // 只用前 received 字节解码，避免粘包导致 decode 失败
        std::vector<uint8_t> decode_buffer(response_buffer.begin(), response_buffer.begin() + received);
        protocol::Message chunk_msg;
        if (!chunk_msg.decode(decode_buffer)) {
            LOG_ERROR("解析响应消息失败");
            success = false;
            break;
        }
        
        // 检查响应类型
        if (chunk_msg.get_operation_type() == protocol::OperationType::ERROR) {
            std::string error_message(
                reinterpret_cast<const char*>(chunk_msg.get_payload().data()),
                chunk_msg.get_payload().size()
            );
            LOG_ERROR("Upload error: %s", error_message.c_str());
            success = false;
            break;
        }
        
        // 更新进度
        uploaded_bytes += current_chunk_size;
        if (progress_callback_) {
            progress_callback_(uploaded_bytes, file_size);
        }
        
        LOG_INFO("Uploaded chunk %zu/%zu: %zu bytes (%0.2f%%)",
                 chunk_index + 1, total_chunks, uploaded_bytes,
                 100.0 * uploaded_bytes / file_size);
                 
        // 在分块之间添加短暂延迟，避免服务器过载
        if (!is_last_chunk) {
            std::this_thread::sleep_for(std::chrono::milliseconds(10));
        }
    }
    
    file.close();
    
    if (success) {
        LOG_INFO("Upload completed successfully: %s -> %s (%zu bytes)",
                 local_file_.c_str(), remote_file_.c_str(), uploaded_bytes);
    } else {
        LOG_ERROR("Upload failed: %s -> %s", local_file_.c_str(), remote_file_.c_str());
    }
    
    return success;
}

} // namespace client
} // namespace ft 