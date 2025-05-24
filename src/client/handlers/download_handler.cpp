#include "download_handler.h"
#include "../../common/utils/logging/logger.h"
#include "../../common/protocol/messages/upload_message.h"
#include "../../common/protocol/messages/download_message.h"
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
                               std::function<void(size_t, size_t)> progress_callback,
                               bool encryption_enabled,
                               const std::vector<uint8_t>& encryption_key,
                               const std::vector<uint8_t>& encryption_iv)
    : local_file_(local_file),
      remote_file_(remote_file),
      progress_callback_(progress_callback),
      encryption_enabled_(encryption_enabled),
      encryption_key_(encryption_key),
      encryption_iv_(encryption_iv) {
}

DownloadHandler::~DownloadHandler() {
}

std::vector<uint8_t> DownloadHandler::decrypt_data(const std::vector<uint8_t>& data) {
    if (!encryption_enabled_ || encryption_key_.empty() || encryption_iv_.empty()) {
        return data;
    }
    
    return ft::utils::Encryption::aes_decrypt(data, encryption_key_, encryption_iv_);
}

bool DownloadHandler::download(ft::network::TcpSocket& socket) {
    LOG_INFO("开始下载: %s -> %s", remote_file_.c_str(), local_file_.c_str());
    
    // 创建本地文件所在的目录
    fs::path local_path(local_file_);
    if (local_path.has_parent_path()) {
        try {
            fs::create_directories(local_path.parent_path());
        } catch (const std::exception& e) {
            LOG_ERROR("创建目录失败: %s, 错误: %s", 
                    local_path.parent_path().c_str(), e.what());
            return false;
        }
    }
    
    // 打开本地文件
    std::ofstream file(local_file_, std::ios::binary);
    if (!file.is_open()) {
        LOG_ERROR("无法创建本地文件: %s", local_file_.c_str());
        return false;
    }
    
    // 验证文件名非空
    if (remote_file_.empty()) {
        LOG_ERROR("远程文件名不能为空");
        file.close();
        return false;
    }
    
    LOG_DEBUG("远程文件名: '%s'", remote_file_.c_str());
    
    // 1. 首先获取文件大小 - 这是一个空请求（length=0）
    protocol::DownloadMessage size_req(remote_file_, 0, 0);
    std::vector<uint8_t> req_buffer;
    
    // 如果启用了加密，设置加密标志并加密数据
    if (encryption_enabled_) {
        // 设置加密标志
        size_req.set_encrypted(true);
        
        // 编码原始消息
        if (!size_req.encode(req_buffer)) {
            LOG_ERROR("编码文件大小请求失败");
            file.close();
            return false;
        }
        
        // 获取负载（跳过协议头）
        std::vector<uint8_t> payload(req_buffer.begin() + sizeof(protocol::ProtocolHeader), 
                                   req_buffer.end());
        
        // 加密负载
        std::vector<uint8_t> encrypted_payload = ft::utils::Encryption::aes_encrypt(payload, encryption_key_, encryption_iv_);
        
        // 创建新的带加密标志的消息
        protocol::Message encrypted_msg(protocol::OperationType::DOWNLOAD);
        encrypted_msg.set_flags(static_cast<uint8_t>(protocol::ProtocolFlags::ENCRYPTED));
        encrypted_msg.set_payload(encrypted_payload.data(), encrypted_payload.size());
        
        // 编码加密消息
        req_buffer.clear();
        if (!encrypted_msg.encode(req_buffer)) {
            LOG_ERROR("编码加密的文件大小请求失败");
            file.close();
            return false;
        }
        
        LOG_DEBUG("文件大小请求已加密");
    } else {
        // 不使用加密
        if (!size_req.encode(req_buffer)) {
            LOG_ERROR("编码文件大小请求失败");
            file.close();
            return false;
        }
    }
    
    // 打印请求详情
    LOG_DEBUG("发送下载请求: 文件='%s', 偏移量=0, 长度=0, 缓冲区大小=%zu", 
             remote_file_.c_str(), req_buffer.size());
    
    // 发送请求前检查连接状态
    if (!socket.is_connected()) {
        LOG_ERROR("发送文件大小请求前套接字未连接");
        file.close();
        return false;
    }
    
    network::SocketError err = socket.send_all(req_buffer.data(), req_buffer.size());
    if (err != network::SocketError::SUCCESS) {
        LOG_ERROR("发送文件大小请求失败: %d", static_cast<int>(err));
        file.close();
        return false;
    }
    
    // 设置较大的超时时间，大文件可能需要更长的时间
    socket.set_recv_timeout(std::chrono::seconds(30));
    
    // 接收响应
    std::vector<uint8_t> resp_buffer(1024 * 4); // 初始缓冲区大小
    
    // 添加接收重试逻辑
    int retry_count = 0;
    const int max_retries = 5;
    bool recv_success = false;
    
    // 2. 接收响应头
    while (retry_count < max_retries && !recv_success) {
        // 检查连接状态
        if (!socket.is_connected()) {
            LOG_ERROR("接收文件大小响应前套接字未连接");
            file.close();
            return false;
        }
        
        // 先接收协议头
        err = socket.recv_all(resp_buffer.data(), sizeof(protocol::ProtocolHeader));
        if (err == network::SocketError::SUCCESS) {
            // 解析协议头
            protocol::ProtocolHeader header;
            std::memcpy(&header, resp_buffer.data(), sizeof(header));
            
            // 保存header字段到局部变量，避免packed结构体直接访问问题
            uint32_t magic_value = header.magic;
            uint8_t type_value = header.type;
            uint32_t length_value = header.length;

            // 验证魔数
            if (magic_value != protocol::PROTOCOL_MAGIC) {
                LOG_ERROR("无效的协议魔数: 0x%08x, 预期: 0x%08x", magic_value, protocol::PROTOCOL_MAGIC);
                retry_count++;
                std::this_thread::sleep_for(std::chrono::milliseconds(200 * retry_count));
                continue;
            }
            
            // 验证负载长度
            if (length_value > 100 * 1024 * 1024) { // 限制100MB
                LOG_ERROR("消息长度过大: %u 字节", length_value);
                retry_count++;
                continue;
            }
            
            LOG_DEBUG("接收到协议头: 类型=%u, 长度=%u", 
                     type_value, length_value);
            
            // 确保缓冲区足够大
            size_t total_size = sizeof(protocol::ProtocolHeader) + length_value;
            if (resp_buffer.size() < total_size) {
                resp_buffer.resize(total_size);
            }
            
            // 接收负载
            if (length_value > 0) {
                err = socket.recv_all(resp_buffer.data() + sizeof(protocol::ProtocolHeader), length_value);
                if (err != network::SocketError::SUCCESS) {
                    LOG_ERROR("接收负载失败: %d", static_cast<int>(err));
                    retry_count++;
                    continue;
                }
            }
            
            recv_success = true;
        } else if (err == network::SocketError::TIMEOUT) {
            retry_count++;
            LOG_WARNING("接收超时，重试 %d/%d", retry_count, max_retries);
            std::this_thread::sleep_for(std::chrono::milliseconds(200 * retry_count));
        } else {
            LOG_ERROR("接收失败: %d", static_cast<int>(err));
            file.close();
            return false;
        }
    }
    
    if (!recv_success) {
        LOG_ERROR("接收响应失败，已达到最大重试次数");
        file.close();
        return false;
    }
    
    // 解析响应消息
    LOG_DEBUG("准备解析响应消息，缓冲区大小: %zu", resp_buffer.size());
    
    // 打印协议头信息用于调试
    if (resp_buffer.size() >= sizeof(protocol::ProtocolHeader)) {
        protocol::ProtocolHeader* debug_header = reinterpret_cast<protocol::ProtocolHeader*>(resp_buffer.data());
        
        // 使用局部变量避免packed结构体访问问题
        uint32_t magic_val = debug_header->magic;
        uint8_t type_val = debug_header->type;
        uint8_t flags_val = debug_header->flags;
        uint32_t length_val = debug_header->length;
        
        LOG_DEBUG("协议头: magic=0x%08x, type=%u, flags=%u, length=%u", 
                 magic_val, type_val, flags_val, length_val);
                 
        // 确保缓冲区大小精确匹配
        size_t expected_size = sizeof(protocol::ProtocolHeader) + length_val;
        if (resp_buffer.size() != expected_size) {
            LOG_WARNING("调整缓冲区大小: 从 %zu 到 %zu", resp_buffer.size(), expected_size);
            resp_buffer.resize(expected_size);
        }
    }
    
    protocol::Message resp_msg;
    if (!resp_msg.decode(resp_buffer)) {
        LOG_ERROR("解析响应消息失败");
        file.close();
        return false;
    }
    
    // 检查是否是加密消息
    bool is_encrypted = (resp_msg.get_flags() & static_cast<uint8_t>(protocol::ProtocolFlags::ENCRYPTED)) != 0;
    
    // 如果是加密消息且启用了加密，则解密
    if (is_encrypted && encryption_enabled_) {
        // 获取加密的负载
        const std::vector<uint8_t>& encrypted_payload = resp_msg.get_payload();
        
        // 解密负载
        std::vector<uint8_t> decrypted_payload = decrypt_data(encrypted_payload);
        
        // 更新消息的负载
        resp_msg.set_payload(decrypted_payload.data(), decrypted_payload.size());
        
        // 清除加密标志
        resp_msg.set_flags(resp_msg.get_flags() & ~static_cast<uint8_t>(protocol::ProtocolFlags::ENCRYPTED));
        
        LOG_DEBUG("响应消息已解密");
    } else if (is_encrypted) {
        LOG_WARNING("收到加密响应但未启用加密");
        file.close();
        return false;
    }
    
    if (resp_msg.get_operation_type() == protocol::OperationType::ERROR) {
        std::string error_message;
        try {
            error_message = std::string(
                reinterpret_cast<const char*>(resp_msg.get_payload().data()),
                resp_msg.get_payload().size()
            );
        } catch (const std::exception& e) {
            error_message = "解析错误消息时发生异常";
        }
        LOG_ERROR("下载错误: %s", error_message.c_str());
        file.close();
        return false;
    }
    
    // 检查是否是有效的下载响应
    if (resp_msg.get_operation_type() != protocol::OperationType::DOWNLOAD) {
        LOG_ERROR("无效的操作类型: 预期 %d, 实际 %d", 
                 static_cast<int>(protocol::OperationType::DOWNLOAD),
                 static_cast<int>(resp_msg.get_operation_type()));
        file.close();
        return false;
    }
    
    // 3. 处理下载响应
    protocol::DownloadMessage download_resp(resp_msg);
    
    // 获取文件大小
    uint64_t file_size = download_resp.get_total_size();
    LOG_INFO("文件大小: %llu 字节", file_size);
    
    if (file_size == 0) {
        LOG_WARNING("远程文件为空: %s", remote_file_.c_str());
        file.close();
        return true;  // 空文件也视为成功
    }
    
    // 计算下载参数
    const size_t chunk_size = 1024 * 1024; // 1MB
    size_t downloaded_bytes = 0;
    bool success = true;
    
    // 如果第一个响应已经包含文件数据，处理它
    const auto& response_data = download_resp.get_response_data();
    if (!response_data.empty()) {
        file.write(reinterpret_cast<const char*>(response_data.data()), response_data.size());
        downloaded_bytes += response_data.size();
        
        if (progress_callback_) {
            progress_callback_(downloaded_bytes, file_size);
        }
        
        LOG_DEBUG("从初始响应中处理了 %zu 字节的数据", response_data.size());
        
        // 如果已是最后一个块，直接完成
        if (download_resp.is_last_chunk()) {
            LOG_INFO("下载完成，共 %zu/%llu 字节", downloaded_bytes, file_size);
            file.close();
            return true;
        }
    } else {
        LOG_WARNING("初始响应不包含数据");
    }
    
    // 4. 分块下载剩余数据
    while (downloaded_bytes < file_size) {
        // 计算当前块大小
        size_t current_chunk_size = std::min(chunk_size, static_cast<size_t>(file_size - downloaded_bytes));
        
        // 创建下载请求
        protocol::DownloadMessage download_req(remote_file_, downloaded_bytes, current_chunk_size);
        req_buffer.clear();
        
        // 如果启用了加密，设置加密标志并加密数据
        if (encryption_enabled_) {
            // 设置加密标志
            download_req.set_encrypted(true);
            
            // 编码原始消息
            if (!download_req.encode(req_buffer)) {
                LOG_ERROR("编码下载请求失败");
                success = false;
                break;
            }
            
            // 获取负载（跳过协议头）
            std::vector<uint8_t> payload(req_buffer.begin() + sizeof(protocol::ProtocolHeader), 
                                       req_buffer.end());
            
            // 加密负载
            std::vector<uint8_t> encrypted_payload = ft::utils::Encryption::aes_encrypt(payload, encryption_key_, encryption_iv_);
            
            // 创建新的带加密标志的消息
            protocol::Message encrypted_msg(protocol::OperationType::DOWNLOAD);
            encrypted_msg.set_flags(static_cast<uint8_t>(protocol::ProtocolFlags::ENCRYPTED));
            encrypted_msg.set_payload(encrypted_payload.data(), encrypted_payload.size());
            
            // 编码加密消息
            req_buffer.clear();
            if (!encrypted_msg.encode(req_buffer)) {
                LOG_ERROR("编码加密的下载请求失败");
                success = false;
                break;
            }
            
            LOG_DEBUG("下载请求已加密");
        } else {
            // 不使用加密
            if (!download_req.encode(req_buffer)) {
                LOG_ERROR("编码下载请求失败");
                success = false;
                break;
            }
        }
        
        // 发送请求
        err = socket.send_all(req_buffer.data(), req_buffer.size());
        if (err != network::SocketError::SUCCESS) {
            LOG_ERROR("发送下载请求失败: %d", static_cast<int>(err));
            success = false;
            break;
        }
        
        // 接收响应
        resp_buffer.resize(sizeof(protocol::ProtocolHeader) + current_chunk_size + 1024);
        retry_count = 0;
        recv_success = false;
        
        while (retry_count < max_retries && !recv_success) {
            // 接收协议头
            err = socket.recv_all(resp_buffer.data(), sizeof(protocol::ProtocolHeader));
            if (err == network::SocketError::SUCCESS) {
                // 解析协议头
                protocol::ProtocolHeader header;
                std::memcpy(&header, resp_buffer.data(), sizeof(header));
                
                // 保存header字段到局部变量，避免packed结构体直接访问问题
                uint32_t magic_value = header.magic;
                uint8_t type_value = header.type;
                uint32_t length_value = header.length;

                // 验证魔数
                if (magic_value != protocol::PROTOCOL_MAGIC) {
                    LOG_ERROR("无效的协议魔数: 0x%08x, 预期: 0x%08x", magic_value, protocol::PROTOCOL_MAGIC);
                    retry_count++;
                    std::this_thread::sleep_for(std::chrono::milliseconds(200 * retry_count));
                    continue;
                }
                
                // 验证操作类型
                if (static_cast<protocol::OperationType>(type_value) != protocol::OperationType::DOWNLOAD) {
                    LOG_ERROR("无效的操作类型: 预期 %d, 实际 %d", 
                             static_cast<int>(protocol::OperationType::DOWNLOAD),
                             static_cast<int>(type_value));
                    retry_count++;
                    continue;
                }
                
                // 验证负载长度
                if (length_value > 100 * 1024 * 1024) { // 限制100MB
                    LOG_ERROR("消息长度过大: %u 字节", length_value);
                    retry_count++;
                    continue;
                }
                
                LOG_DEBUG("接收到协议头: 类型=%u, 长度=%u", 
                         type_value, length_value);
                
                // 确保缓冲区足够大
                size_t total_size = sizeof(protocol::ProtocolHeader) + length_value;
                if (resp_buffer.size() < total_size) {
                    resp_buffer.resize(total_size);
                }
                
                // 接收负载
                if (length_value > 0) {
                    err = socket.recv_all(resp_buffer.data() + sizeof(protocol::ProtocolHeader), length_value);
                    if (err != network::SocketError::SUCCESS) {
                        LOG_ERROR("接收负载失败: %d", static_cast<int>(err));
                        retry_count++;
                        continue;
                    }
                }
                
                recv_success = true;
            } else if (err == network::SocketError::TIMEOUT) {
                retry_count++;
                LOG_WARNING("接收超时，重试 %d/%d", retry_count, max_retries);
                std::this_thread::sleep_for(std::chrono::milliseconds(200 * retry_count));
            } else {
                LOG_ERROR("接收失败: %d", static_cast<int>(err));
                success = false;
                break;
            }
        }
        
        if (!recv_success) {
            LOG_ERROR("接收响应失败，已达到最大重试次数");
            success = false;
            break;
        }
        
        // 解析响应消息
        protocol::Message chunk_msg;
        
        // 从header中获取length
        protocol::ProtocolHeader header;
        std::memcpy(&header, resp_buffer.data(), sizeof(header));
        
        // 保存header字段到局部变量，避免packed结构体直接访问问题
        uint32_t magic_value = header.magic;
        uint8_t type_value = header.type;
        uint32_t length_value = header.length;
        
        // 验证魔数
        if (magic_value != protocol::PROTOCOL_MAGIC) {
            LOG_ERROR("无效的协议魔数: 0x%08x, 预期: 0x%08x", magic_value, protocol::PROTOCOL_MAGIC);
            success = false;
            break;
        }
        
        // 验证操作类型
        if (static_cast<protocol::OperationType>(type_value) != protocol::OperationType::DOWNLOAD) {
            LOG_ERROR("无效的操作类型: 预期 %d, 实际 %d", 
                     static_cast<int>(protocol::OperationType::DOWNLOAD),
                     static_cast<int>(type_value));
            success = false;
            break;
        }
        
        // 验证负载长度
        if (length_value > 100 * 1024 * 1024) { // 限制100MB
            LOG_ERROR("消息长度过大: %u 字节", length_value);
            success = false;
            break;
        }
        
        // 验证缓冲区大小
        size_t expected_size = sizeof(protocol::ProtocolHeader) + length_value;
        if (resp_buffer.size() < expected_size) {
            LOG_ERROR("缓冲区大小不足: 预期至少 %zu 字节, 实际 %zu 字节", 
                     expected_size, resp_buffer.size());
            success = false;
            break;
        }
        // 允许 resp_buffer.size() > expected_size，多余部分下次处理
        if (resp_buffer.size() > expected_size) {
            LOG_DEBUG("缓冲区大于期望: 预期 %zu 字节, 实际 %zu 字节", 
                     expected_size, resp_buffer.size());
        }
        
        // 只用前 expected_size 字节解码，避免粘包导致 decode 失败
        std::vector<uint8_t> decode_buffer(resp_buffer.begin(), resp_buffer.begin() + expected_size);
        if (!chunk_msg.decode(decode_buffer)) {
            LOG_ERROR("解析响应消息失败");
            success = false;
            break;
        }
        
        // 检查是否是加密消息
        is_encrypted = (chunk_msg.get_flags() & static_cast<uint8_t>(protocol::ProtocolFlags::ENCRYPTED)) != 0;
        
        // 如果是加密消息且启用了加密，则解密
        if (is_encrypted && encryption_enabled_) {
            // 获取加密的负载
            const std::vector<uint8_t>& encrypted_payload = chunk_msg.get_payload();
            
            // 解密负载
            std::vector<uint8_t> decrypted_payload = decrypt_data(encrypted_payload);
            
            // 更新消息的负载
            chunk_msg.set_payload(decrypted_payload.data(), decrypted_payload.size());
            
            // 清除加密标志
            chunk_msg.set_flags(chunk_msg.get_flags() & ~static_cast<uint8_t>(protocol::ProtocolFlags::ENCRYPTED));
            
            LOG_DEBUG("响应消息已解密");
        } else if (is_encrypted) {
            LOG_WARNING("收到加密响应但未启用加密");
            success = false;
            break;
        }
        
        if (chunk_msg.get_operation_type() == protocol::OperationType::ERROR) {
            std::string error_message = "未知错误";
            try {
                error_message = std::string(
                    reinterpret_cast<const char*>(chunk_msg.get_payload().data()),
                    chunk_msg.get_payload().size()
                );
            } catch (const std::exception& e) {
                error_message = "解析错误消息异常";
            }
            LOG_ERROR("下载错误: %s", error_message.c_str());
            success = false;
            break;
        }
        
        // 检查操作类型
        if (chunk_msg.get_operation_type() != protocol::OperationType::DOWNLOAD) {
            LOG_ERROR("无效的操作类型: 预期 %d, 实际 %d", 
                     static_cast<int>(protocol::OperationType::DOWNLOAD),
                     static_cast<int>(chunk_msg.get_operation_type()));
            success = false;
            break;
        }
        
        // 处理下载响应
        protocol::DownloadMessage chunk_resp(chunk_msg);
        const auto& chunk_data = chunk_resp.get_response_data();
        
        // 写入文件
        file.write(reinterpret_cast<const char*>(chunk_data.data()), chunk_data.size());
        downloaded_bytes += chunk_data.size();
        
        // 更新进度
        if (progress_callback_) {
            progress_callback_(downloaded_bytes, file_size);
        }
        
        LOG_DEBUG("已下载 %zu/%llu 字节 (%0.2f%%)", 
                 downloaded_bytes, file_size, 100.0 * downloaded_bytes / file_size);
        
        // 检查是否是最后一个块
        if (chunk_resp.is_last_chunk()) {
            LOG_INFO("下载完成，共 %zu/%llu 字节", downloaded_bytes, file_size);
            break;
        }
        
        // 在分块之间添加短暂延迟，避免服务器过载
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
    
    file.close();
    
    if (success) {
        LOG_INFO("下载成功: %s -> %s (%zu 字节)", 
                 remote_file_.c_str(), local_file_.c_str(), downloaded_bytes);
    } else {
        LOG_ERROR("下载失败: %s -> %s", remote_file_.c_str(), local_file_.c_str());
    }
    
    return success;
}

} // namespace client
} // namespace ft 