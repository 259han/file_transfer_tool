#include "download_handler.h"
#include "../../common/utils/logging/logger.h"
#include "../../common/protocol/messages/upload_message.h"
#include <fstream>
#include <filesystem>
#include <chrono>
#include <thread>
#include <cstring>

namespace fs = std::filesystem;

namespace ft {
namespace client {

DownloadHandler::DownloadHandler(const std::string& local_file,
                               const std::string& remote_file,
                               std::function<void(size_t, size_t)> progress_callback)
    : local_file_(local_file),
      remote_file_(remote_file),
      progress_callback_(progress_callback) {
}

DownloadHandler::~DownloadHandler() {
}

bool DownloadHandler::download(ft::network::TcpSocket& socket) {
    LOG_INFO("Starting download: %s -> %s", remote_file_.c_str(), local_file_.c_str());
    
    // 创建本地文件所在的目录
    fs::path local_path(local_file_);
    if (local_path.has_parent_path()) {
        fs::create_directories(local_path.parent_path());
    }
    
    // 打开本地文件
    std::ofstream file(local_file_, std::ios::binary);
    if (!file.is_open()) {
        LOG_ERROR("Failed to create local file: %s", local_file_.c_str());
        return false;
    }
    
    // 发送获取文件大小的请求
    protocol::DownloadMessage size_req(remote_file_, 0, 0);
    std::vector<uint8_t> req_buffer;
    if (!size_req.encode(req_buffer)) {
        LOG_ERROR("Failed to encode file size request");
        file.close();
        return false;
    }
    
    network::SocketError err = socket.send_all(req_buffer.data(), req_buffer.size());
    if (err != network::SocketError::SUCCESS) {
        LOG_ERROR("Failed to send file size request: %d", static_cast<int>(err));
        file.close();
        return false;
    }
    
    // 接收响应
    std::vector<uint8_t> resp_buffer(1024);
    size_t received = 0;
    err = socket.recv(resp_buffer.data(), resp_buffer.size(), received);
    if (err != network::SocketError::SUCCESS) {
        LOG_ERROR("Failed to receive file size response: %d", static_cast<int>(err));
        file.close();
        return false;
    }
    
    // 解析响应
    protocol::Message resp_msg;
    if (!resp_msg.decode(resp_buffer)) {
        LOG_ERROR("Failed to decode file size response");
        file.close();
        return false;
    }
    
    // 检查响应类型
    if (resp_msg.get_operation_type() == protocol::OperationType::ERROR) {
        std::string error_message(
            reinterpret_cast<const char*>(resp_msg.get_payload().data()),
            resp_msg.get_payload().size()
        );
        LOG_ERROR("Download error: %s", error_message.c_str());
        file.close();
        return false;
    }
    
    // 获取文件大小
    uint64_t file_size = 0;
    if (resp_msg.get_payload().size() >= sizeof(uint64_t)) {
        memcpy(&file_size, resp_msg.get_payload().data(), sizeof(uint64_t));
    }
    
    if (file_size == 0) {
        LOG_WARNING("Remote file is empty: %s", remote_file_.c_str());
        file.close();
        return true;
    }
    
    LOG_INFO("File size: %llu bytes", file_size);
    
    // 计算下载参数
    const size_t chunk_size = 1024 * 1024; // 1MB
    size_t downloaded_bytes = 0;
    bool success = true;
    
    // 分块下载
    while (downloaded_bytes < file_size) {
        // 计算当前块大小
        size_t current_chunk_size = std::min(chunk_size, static_cast<size_t>(file_size - downloaded_bytes));
        
        // 创建下载请求
        protocol::DownloadMessage download_req(remote_file_, downloaded_bytes, current_chunk_size);
        req_buffer.clear();
        if (!download_req.encode(req_buffer)) {
            LOG_ERROR("Failed to encode download request");
            success = false;
            break;
        }
        
        // 发送请求
        err = socket.send_all(req_buffer.data(), req_buffer.size());
        if (err != network::SocketError::SUCCESS) {
            LOG_ERROR("Failed to send download request: %d", static_cast<int>(err));
            success = false;
            break;
        }
        
        // 接收响应
        resp_buffer.resize(sizeof(protocol::ProtocolHeader) + current_chunk_size + 1024); // 添加额外空间以容纳协议头和元数据
        received = 0;
        err = socket.recv(resp_buffer.data(), resp_buffer.size(), received);
        if (err != network::SocketError::SUCCESS) {
            LOG_ERROR("Failed to receive download response: %d", static_cast<int>(err));
            success = false;
            break;
        }
        
        // 解析响应
        protocol::Message resp_msg;
        if (!resp_msg.decode(resp_buffer)) {
            LOG_ERROR("Failed to decode download response");
            success = false;
            break;
        }
        
        // 检查响应类型
        if (resp_msg.get_operation_type() == protocol::OperationType::ERROR) {
            std::string error_message(
                reinterpret_cast<const char*>(resp_msg.get_payload().data()),
                resp_msg.get_payload().size()
            );
            LOG_ERROR("Download error: %s", error_message.c_str());
            success = false;
            break;
        }
        
        // 将数据写入文件
        if (!resp_msg.get_payload().empty()) {
            // 如果响应是UploadMessage类型，需要提取文件数据部分
            if (resp_msg.get_operation_type() == protocol::OperationType::UPLOAD) {
                protocol::UploadMessage upload_msg(resp_msg);
                file.seekp(upload_msg.get_offset());
                const auto& file_data = upload_msg.get_file_data();
                file.write(reinterpret_cast<const char*>(file_data.data()), file_data.size());
                downloaded_bytes = upload_msg.get_offset() + file_data.size();
            } else {
                // 直接将负载写入文件
                file.seekp(downloaded_bytes);
                file.write(reinterpret_cast<const char*>(resp_msg.get_payload().data()), resp_msg.get_payload().size());
                downloaded_bytes += resp_msg.get_payload().size();
            }
            
            if (!file.good()) {
                LOG_ERROR("Failed to write data to file at offset %zu", downloaded_bytes);
                success = false;
                break;
            }
            
            // 更新进度
            if (progress_callback_) {
                progress_callback_(downloaded_bytes, file_size);
            }
            
            LOG_INFO("Downloaded: %zu/%llu bytes (%0.2f%%)",
                     downloaded_bytes, file_size, 100.0 * downloaded_bytes / file_size);
        }
        
        // 在分块之间添加短暂延迟，避免服务器过载
        if (downloaded_bytes < file_size) {
            std::this_thread::sleep_for(std::chrono::milliseconds(10));
        }
    }
    
    file.close();
    
    if (success) {
        LOG_INFO("Download completed successfully: %s -> %s (%zu/%llu bytes)",
                 remote_file_.c_str(), local_file_.c_str(), downloaded_bytes, file_size);
    } else {
        LOG_ERROR("Download failed: %s -> %s", remote_file_.c_str(), local_file_.c_str());
        
        // 如果下载失败，删除不完整的文件
        try {
            fs::remove(local_file_);
        } catch (...) {
            // 忽略删除失败的错误
        }
    }
    
    return success;
}

} // namespace client
} // namespace ft 