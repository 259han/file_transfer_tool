#include "upload_handler.h"
#include "../../common/utils/logging/logger.h"
#include <fstream>
#include <filesystem>
#include <cmath>
#include <chrono>
#include <thread>

namespace fs = std::filesystem;

namespace ft {
namespace client {

UploadHandler::UploadHandler(const std::string& local_file,
                           const std::string& remote_file,
                           size_t chunk_size,
                           std::function<void(size_t, size_t)> progress_callback)
    : local_file_(local_file),
      remote_file_(remote_file),
      chunk_size_(chunk_size),
      progress_callback_(progress_callback) {
    
    // 确保分块大小合理
    if (chunk_size_ == 0) {
        chunk_size_ = 1024 * 1024; // 默认分块大小为1MB
    }
}

UploadHandler::~UploadHandler() {
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
        std::vector<char> buffer(current_chunk_size);
        file.seekg(current_offset);
        file.read(buffer.data(), current_chunk_size);
        
        if (!file.good() && !is_last_chunk) {
            LOG_ERROR("Failed to read file data at offset %zu", current_offset);
            success = false;
            break;
        }
        
        // 创建上传消息
        protocol::UploadMessage upload_msg(remote_file_, current_offset, file_size, is_last_chunk);
        upload_msg.set_file_data(buffer.data(), buffer.size());
        
        // 序列化消息
        std::vector<uint8_t> message_buffer;
        if (!upload_msg.encode(message_buffer)) {
            LOG_ERROR("Failed to encode upload message");
            success = false;
            break;
        }
        
        // 发送消息
        network::SocketError err = socket.send_all(message_buffer.data(), message_buffer.size());
        if (err != network::SocketError::SUCCESS) {
            LOG_ERROR("Failed to send upload message: %d", static_cast<int>(err));
            success = false;
            break;
        }
        
        // 等待服务器响应
        std::vector<uint8_t> response_buffer(1024);
        size_t received = 0;
        err = socket.recv(response_buffer.data(), response_buffer.size(), received);
        if (err != network::SocketError::SUCCESS) {
            LOG_ERROR("Failed to receive response: %d", static_cast<int>(err));
            success = false;
            break;
        }
        
        // 解析响应
        protocol::Message response;
        if (!response.decode(response_buffer)) {
            LOG_ERROR("Failed to decode response message");
            success = false;
            break;
        }
        
        // 检查响应类型
        if (response.get_operation_type() == protocol::OperationType::ERROR) {
            std::string error_message(
                reinterpret_cast<const char*>(response.get_payload().data()),
                response.get_payload().size()
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