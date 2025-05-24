#include "upload_handler.h"
#include "../core/client_session.h"
#include "../../common/protocol/messages/upload_message.h"
#include "../../common/protocol/protocol.h"
#include "file_lock_manager.h"
#include "file_version.h"
#include "../core/server_core.h"
#include <filesystem>
#include <fstream>

namespace fs = std::filesystem;

namespace ft {
namespace server {

UploadHandler::UploadHandler(ClientSession& session)
    : ProtocolHandler(session) {
}

bool UploadHandler::handle(const std::vector<uint8_t>& buffer) {
    try {
        LOG_DEBUG("Session %zu: Processing upload message", get_session_id());
        
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
        // 错误发生，忽略文件锁清理中的异常
        // 由于在catch块中无法访问file_path变量，我们不进行锁的释放
        // FileLockManager在析构时会自动清理未释放的锁
        return false;
    }
}

bool UploadHandler::process_upload_chunk(const protocol::UploadMessage& upload_msg) {
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
        
        // 发送错误响应
        protocol::Message error_response(protocol::OperationType::ERROR);
        std::string error_msg = "Failed to acquire file lock: " + filename;
        error_response.set_payload(error_msg.data(), error_msg.size());
        
        std::vector<uint8_t> response_buffer;
        error_response.encode(response_buffer);
        
        try {
            get_socket().send_all(response_buffer.data(), response_buffer.size());
        } catch (const std::exception& e) {
            LOG_ERROR("Session %zu: Exception while sending error response: %s", get_session_id(), e.what());
        }
        
        return false;
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
    
    // 打开文件
    std::ofstream file;
    if (offset == 0) {
        // 新文件，覆盖写入
        file.open(file_path, std::ios::binary | std::ios::trunc);
        LOG_INFO("Session %zu: Opening file for write (new file): %s", get_session_id(), file_path.c_str());
    } else {
        // 追加写入
        file.open(file_path, std::ios::binary | std::ios::in | std::ios::out);
        file.seekp(offset);
        LOG_INFO("Session %zu: Opening file for append at offset %llu: %s", get_session_id(), offset, file_path.c_str());
    }
    
    if (!file.is_open()) {
        LOG_ERROR("Session %zu: Failed to open file for writing: %s", get_session_id(), file_path.c_str());
        
        // 发送错误响应
        protocol::Message error_response(protocol::OperationType::ERROR);
        std::string error_msg = "Failed to open file for writing: " + filename;
        error_response.set_payload(error_msg.data(), error_msg.size());
        
        std::vector<uint8_t> response_buffer;
        error_response.encode(response_buffer);
        
        try {
            get_socket().send_all(response_buffer.data(), response_buffer.size());
        } catch (const std::exception& e) {
            LOG_ERROR("Session %zu: Exception while sending error response: %s", get_session_id(), e.what());
        }
        
        // 释放文件锁
        lock_manager.release_lock(file_path.string());
        return false;
    }
    
    // 写入文件数据
    const std::vector<uint8_t>& file_data = upload_msg.get_file_data();
    if (!file_data.empty()) {
        LOG_INFO("Session %zu: Writing %zu bytes to file", get_session_id(), file_data.size());
        file.write(reinterpret_cast<const char*>(file_data.data()), file_data.size());
        if (!file) {
            LOG_ERROR("Session %zu: Failed to write file data", get_session_id());
            
            // 发送错误响应
            protocol::Message error_response(protocol::OperationType::ERROR);
            std::string error_msg = "Failed to write file data: " + filename;
            error_response.set_payload(error_msg.data(), error_msg.size());
            
            std::vector<uint8_t> response_buffer;
            error_response.encode(response_buffer);
            
            try {
                get_socket().send_all(response_buffer.data(), response_buffer.size());
            } catch (const std::exception& e) {
                LOG_ERROR("Session %zu: Exception while sending error response: %s", get_session_id(), e.what());
            }
            
            // 释放文件锁
            lock_manager.release_lock(file_path.string());
            return false;
        }
    }
    
    file.close();
    LOG_INFO("Session %zu: File closed successfully", get_session_id());
    
    // 发送响应
    if (!send_upload_response(is_last_chunk)) {
        // 释放文件锁
        lock_manager.release_lock(file_path.string());
        return false;
    }
    
    LOG_INFO("Session %zu: Upload chunk processed successfully for file %s", get_session_id(), filename.c_str());

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