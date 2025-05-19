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
                               std::function<void(size_t, size_t)> progress_callback)
    : local_file_(local_file),
      remote_file_(remote_file),
      progress_callback_(progress_callback) {
}

DownloadHandler::~DownloadHandler() {
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
    if (!size_req.encode(req_buffer)) {
        LOG_ERROR("编码文件大小请求失败");
        file.close();
        return false;
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
    size_t received = 0;
    
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
            
            // 验证魔数
            uint32_t header_magic = header.magic;
            uint32_t expected_magic = protocol::PROTOCOL_MAGIC;
            if (header_magic != expected_magic) {
                LOG_ERROR("无效的协议魔数: 0x%08x, 预期: 0x%08x", header_magic, expected_magic);
                retry_count++;
                std::this_thread::sleep_for(std::chrono::milliseconds(200 * retry_count));
                continue;
            }
            
            // 使用临时变量存储 header 的字段值
            uint8_t header_type = header.type;
            uint8_t header_flags = header.flags;
            uint32_t header_length = header.length;
            
            // 验证负载长度
            if (header_length > 100 * 1024 * 1024) { // 限制100MB
                LOG_ERROR("消息长度过大: %u 字节", header_length);
                retry_count++;
                continue;
            }
            
            LOG_DEBUG("接收到协议头: 类型=%u, 标志=%u, 长度=%u", 
                     header_type, header_flags, header_length);
            
            // 确保缓冲区足够大
            size_t total_size = sizeof(protocol::ProtocolHeader) + header_length;
            if (resp_buffer.size() < total_size) {
                resp_buffer.resize(total_size);
            }
            
            // 接收负载
            if (header_length > 0) {
                err = socket.recv_all(resp_buffer.data() + sizeof(protocol::ProtocolHeader), header_length);
                if (err != network::SocketError::SUCCESS) {
                    LOG_ERROR("接收负载失败: %d", static_cast<int>(err));
                    retry_count++;
                    std::this_thread::sleep_for(std::chrono::milliseconds(300 * retry_count));
                    continue;
                }
            }
            
            received = total_size;
            recv_success = true;
            LOG_DEBUG("成功接收文件大小响应: %zu 字节", received);
        } else if (err == network::SocketError::TIMEOUT) {
            retry_count++;
            LOG_WARNING("接收文件大小响应超时，重试 %d/%d", retry_count, max_retries);
            std::this_thread::sleep_for(std::chrono::milliseconds(300 * retry_count));
        } else {
            LOG_ERROR("接收文件大小响应失败: %d", static_cast<int>(err));
            file.close();
            return false;
        }
    }
    
    if (!recv_success) {
        LOG_ERROR("在 %d 次重试后依然无法接收文件大小响应", max_retries);
        file.close();
        return false;
    }
    
    // 调整缓冲区大小为实际接收的大小
    resp_buffer.resize(received);
    
    // 解析响应
    protocol::Message resp_msg;
    if (!resp_msg.decode(resp_buffer)) {
        LOG_ERROR("解码文件大小响应失败");
        file.close();
        return false;
    }
    
    // 检查是否是错误响应
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
    if (downloaded_bytes < file_size) {
        // 读取文件直到完整接收或出错
        while (downloaded_bytes < file_size) {
            // 首先检查连接状态
            if (!socket.is_connected()) {
                LOG_ERROR("下载过程中套接字断开连接，已下载 %zu/%llu 字节", downloaded_bytes, file_size);
                success = false;
                break;
            }
            
            // 计算当前块大小
            size_t current_chunk_size = std::min(chunk_size, static_cast<size_t>(file_size - downloaded_bytes));
            
            // 创建下载请求
            protocol::DownloadMessage download_req(remote_file_, downloaded_bytes, current_chunk_size);
            req_buffer.clear();
            if (!download_req.encode(req_buffer)) {
                LOG_ERROR("编码下载请求失败");
                success = false;
                break;
            }
            
            LOG_DEBUG("发送下载请求: 文件='%s', 偏移量=%llu, 长度=%zu", 
                    remote_file_.c_str(), downloaded_bytes, current_chunk_size);
            
            // 发送请求
            err = socket.send_all(req_buffer.data(), req_buffer.size());
            if (err != network::SocketError::SUCCESS) {
                LOG_ERROR("发送下载请求失败: %d", static_cast<int>(err));
                success = false;
                break;
            }
            
            // 接收响应 - 与前面类似的逻辑
            resp_buffer.resize(sizeof(protocol::ProtocolHeader) + current_chunk_size + 1024);
            received = 0;
            retry_count = 0;
            recv_success = false;
            
            while (retry_count < max_retries && !recv_success) {
                if (!socket.is_connected()) {
                    LOG_ERROR("接收下载响应前套接字断开连接");
                    success = false;
                    break;
                }
                
                // 先接收协议头
                err = socket.recv_all(resp_buffer.data(), sizeof(protocol::ProtocolHeader));
                if (err == network::SocketError::SUCCESS) {
                    // 解析协议头
                    protocol::ProtocolHeader header;
                    std::memcpy(&header, resp_buffer.data(), sizeof(header));
                    
                    // 验证魔数
                    uint32_t header_magic = header.magic;
                    uint32_t expected_magic = protocol::PROTOCOL_MAGIC;
                    if (header_magic != expected_magic) {
                        LOG_ERROR("无效的协议魔数: 0x%08x, 预期: 0x%08x", header_magic, expected_magic);
                        retry_count++;
                        std::this_thread::sleep_for(std::chrono::milliseconds(200 * retry_count));
                        continue;
                    }
                    
                    // 使用临时变量存储 header 的字段值
                    uint8_t header_type = header.type;
                    uint8_t header_flags = header.flags;
                    uint32_t header_length = header.length;
                    
                    // 确保缓冲区足够大
                    size_t total_size = sizeof(protocol::ProtocolHeader) + header_length;
                    if (resp_buffer.size() < total_size) {
                        resp_buffer.resize(total_size);
                    }
                    
                    // 接收剩余的负载
                    if (header_length > 0) {
                        err = socket.recv_all(resp_buffer.data() + sizeof(protocol::ProtocolHeader), header_length);
                        if (err != network::SocketError::SUCCESS) {
                            LOG_ERROR("接收负载失败: %d", static_cast<int>(err));
                            retry_count++;
                            std::this_thread::sleep_for(std::chrono::milliseconds(300 * retry_count));
                            continue;
                        }
                    }
                    
                    received = total_size;
                    recv_success = true;
                    LOG_DEBUG("成功接收下载响应: %zu 字节", received);
                } else if (err == network::SocketError::TIMEOUT) {
                    retry_count++;
                    LOG_WARNING("接收下载响应超时，重试 %d/%d", retry_count, max_retries);
                    std::this_thread::sleep_for(std::chrono::milliseconds(300 * retry_count));
                } else {
                    LOG_ERROR("接收下载响应失败: %d", static_cast<int>(err));
                    success = false;
                    break;
                }
            }
            
            if (!recv_success) {
                LOG_ERROR("多次重试后无法接收下载响应");
                success = false;
                break;
            }
            
            // 解码收到的消息
            resp_buffer.resize(received);
            protocol::Message chunk_msg;
            if (!chunk_msg.decode(resp_buffer)) {
                LOG_ERROR("解码数据块响应失败");
                success = false;
                break;
            }
            
            // 检查错误响应
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
            
            if (chunk_data.empty()) {
                LOG_WARNING("接收到空的数据块");
            } else {
                // 处理偏移量
                uint64_t offset = chunk_resp.get_offset();
                if (offset != downloaded_bytes) {
                    LOG_WARNING("数据偏移量不匹配: 预期=%zu, 实际=%llu", 
                               downloaded_bytes, offset);
                    file.seekp(offset);
                }
                
                // 写入数据
                file.write(reinterpret_cast<const char*>(chunk_data.data()), chunk_data.size());
                
                // 更新下载计数
                downloaded_bytes = offset + chunk_data.size();
                
                // 进度回调
                if (progress_callback_) {
                    progress_callback_(downloaded_bytes, file_size);
                }
                
                LOG_DEBUG("下载进度: %zu/%llu 字节 (%.2f%%)", 
                         downloaded_bytes, file_size, 
                         100.0 * downloaded_bytes / file_size);
            }
            
            // 检查是否为最后一个块
            if (chunk_resp.is_last_chunk()) {
                LOG_INFO("接收到最后一个数据块");
                break;
            }
            
            // 适当延迟，避免服务器压力
            std::this_thread::sleep_for(std::chrono::milliseconds(30));
        }
    }
    
    file.close();
    
    if (success) {
        LOG_INFO("下载成功: %s -> %s (%zu/%llu 字节)",
                 remote_file_.c_str(), local_file_.c_str(), downloaded_bytes, file_size);
    } else {
        LOG_ERROR("下载失败: %s -> %s", remote_file_.c_str(), local_file_.c_str());
        
        // 删除不完整文件
        try {
            fs::remove(local_file_);
        } catch (...) {
            // 忽略
        }
    }
    
    return success;
}

} // namespace client
} // namespace ft 