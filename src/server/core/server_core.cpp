#include "server_core.h"
#include "../../common/protocol/messages/upload_message.h"
#include "../../common/protocol/messages/download_message.h"
#include "../../common/protocol/messages/key_exchange_message.h"
#include "../../common/utils/crypto/encryption.h"
#include <filesystem>
#include <fstream>
#include <chrono>
#include <cstring>
#include <openssl/dh.h>
#include <openssl/bn.h>

namespace fs = std::filesystem;

namespace ft {
namespace server {

// ClientSession静态成员初始化
std::atomic<size_t> ClientSession::next_session_id_(1);

// ClientSession实现
ClientSession::ClientSession(std::unique_ptr<network::TcpSocket> socket)
    : session_id_(next_session_id_++),
      socket_(std::move(socket)),
      thread_(),
      running_(false),
      encryption_enabled_(false),
      encryption_key_(),
      encryption_iv_(),
      dh_private_key_(),
      key_exchange_completed_(false) {
    
    // 确保socket有效
    if (socket_ && socket_->is_connected()) {
        // 记录初始化信息
        LOG_DEBUG("ClientSession %zu: Created with socket fd=%d, remote=%s:%d", 
                 session_id_,
                 socket_->get_fd(),
                 socket_->get_remote_address().c_str(),
                 socket_->get_remote_port());
    } else {
        if (!socket_) {
            LOG_WARNING("ClientSession %zu: Created with null socket", session_id_);
        } else {
            LOG_WARNING("ClientSession %zu: Created with disconnected socket fd=%d", 
                       session_id_, socket_->get_fd());
        }
    }
}

ClientSession::~ClientSession() {
    stop();
}

void ClientSession::start() {
    if (running_) {
        return;
    }
    
    running_ = true;
    thread_ = std::thread(&ClientSession::process, this);
}

void ClientSession::stop() {
    running_ = false;
    
    if (socket_) {
        socket_->close();
    }
    
    if (thread_.joinable()) {
        thread_.join();
    }
}

std::string ClientSession::get_client_address() const {
    if (!socket_) {
        return "unknown";
    }
    
    return socket_->get_remote_address() + ":" + std::to_string(socket_->get_remote_port());
}

size_t ClientSession::get_session_id() const {
    return session_id_;
}

bool ClientSession::is_connected() const {
    return running_ && socket_ && socket_->is_connected();
}

void ClientSession::process() {
    try {
        // 连接握手
        LOG_INFO("Session %zu: Started for client %s", session_id_, get_client_address().c_str());
        
        // 首先检查客户端是否还连接，添加更详细的日志
        if (!socket_) {
            LOG_WARNING("Session %zu: Socket is null during initialization", session_id_);
            return;
        }
        
        if (!socket_->is_connected()) {
            LOG_WARNING("Session %zu: Client disconnected during initialization, fd=%d", 
                      session_id_, socket_->get_fd());
            return;
        }
        
        int socket_fd = socket_->get_fd();
        LOG_DEBUG("Session %zu: Socket fd=%d is valid and connected", 
                 session_id_, socket_fd);
        
        LOG_INFO("Session %zu: Client socket connected, waiting for heartbeat", session_id_);
        
        // 连接建立后延迟一点时间，让客户端先准备好
        std::this_thread::sleep_for(std::chrono::milliseconds(50));
        
        // 为了增加健壮性，在session开始时直接设置socket超时较短
        socket_->set_recv_timeout(std::chrono::milliseconds(3000));
        
        // 连接建立后等待更长时间，让客户端准备好发送心跳
        // 但每200ms检查一次连接状态，避免等待断开的连接
        int wait_intervals = 6; // 6次，每次200ms，总共1200ms
        for (int i = 0; i < wait_intervals; i++) {
            if (!socket_ || !socket_->is_connected()) {
                LOG_WARNING("Session %zu: Client disconnected during wait period (%d/6)", 
                           session_id_, i+1);
                return;
            }
            
            // 每隔200ms检查一次socket状态
            std::this_thread::sleep_for(std::chrono::milliseconds(200));
            
            // 额外检查socket状态，更主动地发现问题
            if (socket_) {
                // 主动检测TCP连接状态
                int error = 0;
                socklen_t len = sizeof(error);
                if (getsockopt(socket_->get_fd(), SOL_SOCKET, SO_ERROR, &error, &len) == 0) {
                    if (error != 0) {
                        LOG_WARNING("Session %zu: Socket error detected during wait: %s (errno=%d)", 
                                   session_id_, strerror(error), error);
                        return;
                    }
                }
                
                // 验证socket是否连接
                if (!socket_->is_connected()) {
                    LOG_WARNING("Session %zu: Connection lost during wait interval %d/6", 
                               session_id_, i+1);
                    return;
                }
            }
        }
        LOG_INFO("Session %zu: Waited 1200ms after session start to ensure client readiness", 
                session_id_);
        
        int consecutive_errors = 0;
        const int max_consecutive_errors = 5;  // 允许的最大连续错误数
        
        while (running_) {
            // 检查套接字状态
            if (!socket_ || !socket_->is_connected()) {
                LOG_WARNING("Session %zu: Socket disconnected, exiting session", session_id_);
                break;
            }
            
            // 设置单次接收超时，防止永久阻塞
            socket_->set_recv_timeout(std::chrono::milliseconds(5000));
            
            // 接收协议头
            std::vector<uint8_t> header_buffer(sizeof(protocol::ProtocolHeader));
            LOG_DEBUG("Session %zu: Waiting to receive protocol header (%zu bytes)...", 
                     session_id_, sizeof(protocol::ProtocolHeader));
            
            // 添加协议头大小的详细信息
            LOG_DEBUG("Session %zu: Protocol header size details - "
                     "magic(4) + type(1) + flags(1) + length(4) + checksum(4) + reserved(2) = %zu bytes", 
                     session_id_, sizeof(protocol::ProtocolHeader));
                     
            // 确保结构体大小正确
            LOG_DEBUG("Session %zu: Actual protocol header size: %zu bytes", 
                     session_id_, sizeof(protocol::ProtocolHeader));

            // 增加错误处理
            network::SocketError err = network::SocketError::SUCCESS;
            
            try {
                err = socket_->recv_all(header_buffer.data(), header_buffer.size());
            } catch (const std::exception& e) {
                LOG_ERROR("Session %zu: Exception during header receive: %s", session_id_, e.what());
                // 增加连续错误计数
                consecutive_errors++;
                if (consecutive_errors >= max_consecutive_errors) {
                    LOG_ERROR("Session %zu: Too many consecutive errors, exiting session", session_id_);
                    break;
                }
                std::this_thread::sleep_for(std::chrono::milliseconds(100));
                continue;
            }
            
            if (err != network::SocketError::SUCCESS) {
                if (err == network::SocketError::CLOSED) {
                    LOG_INFO("Session %zu: Connection closed by client", session_id_);
                    break;  // 连接关闭，立即退出循环
                } else {
                    // 添加更详细的错误信息
                    char err_buf[128] = {0};
                    strerror_r(errno, err_buf, sizeof(err_buf));
                    LOG_ERROR("Session %zu: Failed to receive header: %d, socket connected: %d, errno: %d (%s)", 
                             session_id_, static_cast<int>(err), socket_->is_connected(), 
                             errno, err_buf);
                             
                    LOG_DEBUG("Session %zu: Socket details - local: %s:%d, remote: %s:%d", 
                             session_id_, 
                             socket_->get_local_address().c_str(), 
                             socket_->get_local_port(),
                             socket_->get_remote_address().c_str(),
                             socket_->get_remote_port());
                    
                    // 增加连续错误计数
                    consecutive_errors++;
                    if (consecutive_errors >= max_consecutive_errors) {
                        LOG_ERROR("Session %zu: Too many consecutive errors, exiting session", session_id_);
                        break;
                    }
                }
                
                // 给套接字一些时间恢复
                std::this_thread::sleep_for(std::chrono::milliseconds(200));
                
                // 如果是一些可恢复的错误，可以继续尝试
                if (err == network::SocketError::TIMEOUT) {
                    LOG_WARNING("Session %zu: Receive timeout, retrying...", session_id_);
                    continue;
                }
                
                // 其他不可恢复的错误
                LOG_ERROR("Session %zu: Unrecoverable socket error, exiting session", session_id_);
                break;
            }
            
            // 重置连续错误计数
            consecutive_errors = 0;
            
            // 添加调试信息 - 打印接收到的原始字节
            LOG_DEBUG("Session %zu: Received header bytes (hex): ", session_id_);
            for (size_t i = 0; i < header_buffer.size(); i += 4) {
                char debug_buf[128];
                snprintf(debug_buf, sizeof(debug_buf), "  %02x %02x %02x %02x", 
                        i < header_buffer.size() ? header_buffer[i] : 0,
                        i+1 < header_buffer.size() ? header_buffer[i+1] : 0,
                        i+2 < header_buffer.size() ? header_buffer[i+2] : 0,
                        i+3 < header_buffer.size() ? header_buffer[i+3] : 0);
                LOG_DEBUG("Session %zu: %s", session_id_, debug_buf);
            }
            
            // 解析协议头
            protocol::ProtocolHeader header;
            std::memcpy(&header, header_buffer.data(), sizeof(header));
            
            // 复制header字段到局部变量，避免结构体对齐问题
            uint32_t magic_value = header.magic;
            uint8_t type_value = header.type;
            uint8_t flags_value = header.flags;
            uint32_t length_value = header.length;
            uint32_t checksum_value = header.checksum;
            
            // 检查魔数
            if (magic_value != protocol::PROTOCOL_MAGIC) {
                LOG_ERROR("Session %zu: Invalid protocol magic: 0x%08x, expected: 0x%08x", 
                          session_id_, magic_value, protocol::PROTOCOL_MAGIC);
                consecutive_errors++;
                if (consecutive_errors >= max_consecutive_errors) {
                    LOG_ERROR("Session %zu: Too many consecutive errors, exiting session", session_id_);
                    break;
                }
                continue;
            }
            
            LOG_DEBUG("Session %zu: Received valid header - magic: 0x%08x, type: %d, flags: %d, length: %u, checksum: 0x%08x", 
                     session_id_, magic_value, type_value, flags_value, length_value, checksum_value);
            
            // 检查长度是否合理，防止恶意/损坏的包
            if (length_value > 100 * 1024 * 1024) {  // 限制100MB
                LOG_ERROR("Session %zu: Message length too large: %u bytes", session_id_, length_value);
                consecutive_errors++;
                if (consecutive_errors >= max_consecutive_errors) {
                    LOG_ERROR("Session %zu: Too many consecutive errors, exiting session", session_id_);
                    break;
                }
                continue;
            }
            
            // 接收消息体
            std::vector<uint8_t> message_buffer(sizeof(protocol::ProtocolHeader) + length_value);
            std::memcpy(message_buffer.data(), header_buffer.data(), sizeof(protocol::ProtocolHeader));
            
            if (length_value > 0) {
                LOG_DEBUG("Session %zu: Receiving message body of length %u", session_id_, length_value);
                err = socket_->recv_all(message_buffer.data() + sizeof(protocol::ProtocolHeader), length_value);
                if (err != network::SocketError::SUCCESS) {
                    LOG_ERROR("Session %zu: Failed to receive message body: %d", session_id_, static_cast<int>(err));
                    consecutive_errors++;
                    if (consecutive_errors >= max_consecutive_errors) {
                        LOG_ERROR("Session %zu: Too many consecutive errors, exiting session", session_id_);
                        break;
                    }
                    continue;
                }
                LOG_DEBUG("Session %zu: Message body received successfully", session_id_);
            }
            
            // 根据操作类型处理消息
            protocol::OperationType op_type = static_cast<protocol::OperationType>(type_value);
            LOG_INFO("Session %zu: Processing message of type: %d", session_id_, static_cast<int>(op_type));
            
            bool message_handled = false;
            try {
                switch (op_type) {
                    case protocol::OperationType::UPLOAD:
                        message_handled = handle_upload(message_buffer);
                        break;
                    
                    case protocol::OperationType::DOWNLOAD:
                        message_handled = handle_download(message_buffer);
                        break;
                    
                    case protocol::OperationType::KEY_EXCHANGE:
                        message_handled = handle_key_exchange(message_buffer);
                        break;
                    
                    case protocol::OperationType::HEARTBEAT:
                        // 发送心跳响应
                        LOG_DEBUG("Session %zu: Received heartbeat, preparing response", session_id_);
                        try {
                            // 创建新的心跳响应消息而不是直接回传接收到的消息
                            protocol::Message response(protocol::OperationType::HEARTBEAT);
                            std::vector<uint8_t> response_buffer;
                            if (!response.encode(response_buffer)) {
                                LOG_ERROR("Session %zu: Failed to encode heartbeat response", session_id_);
                                message_handled = false;
                                break;
                            }
                            
                            // 添加详细调试信息
                            LOG_DEBUG("Session %zu: Heartbeat response encoded, size: %zu bytes", 
                                     session_id_, response_buffer.size());
                            
                            // 记录发送的心跳响应头部
                            if (response_buffer.size() >= sizeof(protocol::ProtocolHeader)) {
                                protocol::ProtocolHeader* sent_header = 
                                    reinterpret_cast<protocol::ProtocolHeader*>(response_buffer.data());
                                
                                // 由于ProtocolHeader是packed结构体，需要复制成员变量而不是直接引用
                                uint32_t sent_magic = sent_header->magic;
                                uint8_t sent_type = sent_header->type;
                                uint32_t sent_length = sent_header->length;
                                
                                // 确保magic和type值正确 - 双重检查，确保字段被正确初始化
                                if (sent_magic != protocol::PROTOCOL_MAGIC) {
                                    LOG_ERROR("Session %zu: Invalid magic in heartbeat response: 0x%08x, correcting", 
                                             session_id_, sent_magic);
                                    sent_header->magic = protocol::PROTOCOL_MAGIC;
                                    sent_magic = protocol::PROTOCOL_MAGIC;
                                }
                                
                                if (sent_type != static_cast<uint8_t>(protocol::OperationType::HEARTBEAT)) {
                                    LOG_ERROR("Session %zu: Invalid type in heartbeat response: %d, correcting", 
                                             session_id_, sent_type);
                                    sent_header->type = static_cast<uint8_t>(protocol::OperationType::HEARTBEAT);
                                    sent_type = static_cast<uint8_t>(protocol::OperationType::HEARTBEAT);
                                }
                                
                                LOG_DEBUG("Session %zu: Heartbeat response header validated - "
                                         "magic: 0x%08x, type: %d, length: %u", 
                                         session_id_, sent_magic, sent_type, sent_length);
                            } else {
                                LOG_ERROR("Session %zu: Response buffer too small: %zu bytes", 
                                          session_id_, response_buffer.size());
                                message_handled = false;
                                break;
                            }
                            
                            // 检查socket状态
                            if (!socket_ || !socket_->is_connected()) {
                                LOG_ERROR("Session %zu: Socket not connected for heartbeat response", session_id_);
                                message_handled = false;
                                break;
                            }
                            
                            // 确保没有错误发生前先设置为已处理 - 即使心跳响应发送失败，也视为处理过消息
                            // 这样服务器不会因为心跳响应问题而立即断开连接
                            message_handled = true;
                            
                            // 设置发送超时，防止永久阻塞
                            socket_->set_send_timeout(std::chrono::milliseconds(3000));
                            
                            // 增加短暂延迟, 确保客户端已准备好接收响应
                            std::this_thread::sleep_for(std::chrono::milliseconds(50));
                            
                            // 尝试发送心跳响应，失败时记录警告但不中断会话
                            int send_retry = 0;
                            const int max_send_retries = 3;
                            bool send_success = false;
                            
                            while (send_retry < max_send_retries && !send_success) {
                                try {
                                    // 每次发送前检查连接状态
                                    if (!socket_ || !socket_->is_connected()) {
                                        LOG_WARNING("Session %zu: Socket disconnected during heartbeat response retry", 
                                                  session_id_);
                                        break;
                                    }
                                    
                                    network::SocketError send_err = socket_->send_all(response_buffer.data(), response_buffer.size());
                                    if (send_err == network::SocketError::SUCCESS) {
                                        send_success = true;
                                        LOG_DEBUG("Session %zu: Heartbeat response sent successfully", session_id_);
                                    } else {
                                        send_retry++;
                                        
                                        if (send_retry < max_send_retries) {
                                            LOG_WARNING("Session %zu: Failed to send heartbeat response: %d, retry %d/%d", 
                                                       session_id_, static_cast<int>(send_err), send_retry, max_send_retries);
                                            
                                            // 添加短暂延迟后重试
                                            std::this_thread::sleep_for(std::chrono::milliseconds(50));
                                        } else {
                                            LOG_WARNING("Session %zu: Failed to send heartbeat response after %d retries", 
                                                      session_id_, max_send_retries);
                                        }
                                    }
                                } catch (const std::exception& e) {
                                    send_retry++;
                                    
                                    if (send_retry < max_send_retries) {
                                        LOG_WARNING("Session %zu: Exception during heartbeat send: %s, retry %d/%d", 
                                                  session_id_, e.what(), send_retry, max_send_retries);
                                        
                                        // 添加短暂延迟后重试
                                        std::this_thread::sleep_for(std::chrono::milliseconds(50));
                                    } else {
                                        LOG_WARNING("Session %zu: Exception during heartbeat send after %d retries: %s", 
                                                  session_id_, max_send_retries, e.what());
                                    }
                                }
                            }
                        } catch (const std::exception& e) {
                            LOG_ERROR("Session %zu: Exception while preparing heartbeat response: %s", 
                                     session_id_, e.what());
                            message_handled = false;
                        }
                        break;
                    
                    default:
                        LOG_WARNING("Session %zu: Unknown operation type: %d", session_id_, static_cast<int>(op_type));
                        message_handled = false;
                        break;
                }
            } catch (const std::exception& e) {
                LOG_ERROR("Session %zu: Exception while processing message: %s", session_id_, e.what());
                message_handled = false;
            }
            
            if (!message_handled) {
                consecutive_errors++;
                if (consecutive_errors >= max_consecutive_errors) {
                    LOG_ERROR("Session %zu: Too many consecutive errors, exiting session", session_id_);
                    break;
                }
            } else {
                // 成功处理消息后重置连续错误计数
                consecutive_errors = 0;
            }
            
            // 短暂延迟，给客户端一些处理时间
            std::this_thread::sleep_for(std::chrono::milliseconds(10));
        }
    } catch (const std::exception& e) {
        LOG_ERROR("Session %zu: Exception: %s", session_id_, e.what());
    }
    
    LOG_INFO("Session %zu: Ended for client %s", session_id_, get_client_address().c_str());
}

bool ClientSession::handle_upload(const std::vector<uint8_t>& buffer) {
    try {
        // 添加额外调试信息
        LOG_INFO("Session %zu: Received upload message, buffer size: %zu", session_id_, buffer.size());
        
        // 解析上传消息
        protocol::Message msg;
        if (!msg.decode(buffer)) {
            LOG_ERROR("Session %zu: Failed to decode upload message", session_id_);
            
            // 发送错误响应
            protocol::Message error_response(protocol::OperationType::ERROR);
            std::string error_msg = "Failed to decode upload message";
            error_response.set_payload(error_msg.data(), error_msg.size());
            
            std::vector<uint8_t> response_buffer;
            error_response.encode(response_buffer);
            
            try {
                socket_->send_all(response_buffer.data(), response_buffer.size());
            } catch (const std::exception& e) {
                LOG_ERROR("Session %zu: Exception while sending error response: %s", session_id_, e.what());
            }
            
            return false;
        }
        
        // 打印收到的消息信息
        uint8_t type_value = static_cast<uint8_t>(msg.get_operation_type());
        uint8_t flags_value = msg.get_flags();
        LOG_INFO("Session %zu: Decoded message - type: %d, flags: %d", 
                 session_id_, type_value, flags_value);
        
        // 检查是否需要解密
        bool is_encrypted = (flags_value & static_cast<uint8_t>(protocol::ProtocolFlags::ENCRYPTED)) != 0;
        if (is_encrypted && encryption_enabled_ && key_exchange_completed_) {
            LOG_DEBUG("Session %zu: Message is encrypted, decrypting payload", session_id_);
            
            // 获取负载并解密
            const std::vector<uint8_t>& encrypted_payload = msg.get_payload();
            std::vector<uint8_t> decrypted_payload = decrypt_data(encrypted_payload);
            
            // 更新消息的负载
            msg.set_payload(decrypted_payload.data(), decrypted_payload.size());
            
            // 清除加密标志
            msg.set_flags(flags_value & ~static_cast<uint8_t>(protocol::ProtocolFlags::ENCRYPTED));
            
            LOG_DEBUG("Session %zu: Payload decrypted successfully, size: %zu -> %zu", 
                      session_id_, encrypted_payload.size(), decrypted_payload.size());
        } else if (is_encrypted) {
            LOG_WARNING("Session %zu: Message is encrypted but encryption is not ready", session_id_);
            return false;
        }
        
        protocol::UploadMessage upload_msg(msg);
        
        // 获取文件信息
        std::string filename = upload_msg.get_filename();
        uint64_t offset = upload_msg.get_offset();
        uint64_t total_size = upload_msg.get_total_size();
        bool is_last_chunk = upload_msg.is_last_chunk();
        
        LOG_INFO("Session %zu: Received upload request for file %s, offset: %llu, chunk size: %zu, total size: %llu, last chunk: %d",
                 session_id_, filename.c_str(), offset, upload_msg.get_file_data().size(), total_size, is_last_chunk);
        
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
                 session_id_, storage_path.c_str(), file_path.c_str());
        
        if (!fs::exists(storage_path)) {
            LOG_INFO("Session %zu: Creating storage directory: %s", session_id_, storage_path.c_str());
            fs::create_directories(storage_path);
        }
        
        // 打开文件
        std::ofstream file;
        if (offset == 0) {
            // 新文件，覆盖写入
            file.open(file_path, std::ios::binary | std::ios::trunc);
            LOG_INFO("Session %zu: Opening file for write (new file): %s", session_id_, file_path.c_str());
        } else {
            // 追加写入
            file.open(file_path, std::ios::binary | std::ios::in | std::ios::out);
            file.seekp(offset);
            LOG_INFO("Session %zu: Opening file for append at offset %llu: %s", session_id_, offset, file_path.c_str());
        }
        
        if (!file.is_open()) {
            LOG_ERROR("Session %zu: Failed to open file for writing: %s", session_id_, file_path.c_str());
            
            // 发送错误响应
            protocol::Message error_response(protocol::OperationType::ERROR);
            std::string error_msg = "Failed to open file for writing: " + filename;
            error_response.set_payload(error_msg.data(), error_msg.size());
            
            std::vector<uint8_t> response_buffer;
            error_response.encode(response_buffer);
            
            try {
                socket_->send_all(response_buffer.data(), response_buffer.size());
            } catch (const std::exception& e) {
                LOG_ERROR("Session %zu: Exception while sending error response: %s", session_id_, e.what());
            }
            
            return false;
        }
        
        // 写入文件数据
        const std::vector<uint8_t>& file_data = upload_msg.get_file_data();
        if (!file_data.empty()) {
            LOG_INFO("Session %zu: Writing %zu bytes to file", session_id_, file_data.size());
            file.write(reinterpret_cast<const char*>(file_data.data()), file_data.size());
            if (!file) {
                LOG_ERROR("Session %zu: Failed to write file data", session_id_);
                
                // 发送错误响应
                protocol::Message error_response(protocol::OperationType::ERROR);
                std::string error_msg = "Failed to write file data: " + filename;
                error_response.set_payload(error_msg.data(), error_msg.size());
                
                std::vector<uint8_t> response_buffer;
                error_response.encode(response_buffer);
                
                try {
                    socket_->send_all(response_buffer.data(), response_buffer.size());
                } catch (const std::exception& e) {
                    LOG_ERROR("Session %zu: Exception while sending error response: %s", session_id_, e.what());
                }
                
                return false;
            }
        }
        
        file.close();
        LOG_INFO("Session %zu: File closed successfully", session_id_);
        
        // 修改发送响应的部分，如果启用了加密，则加密响应
        protocol::Message response_msg(protocol::OperationType::UPLOAD);
        // 设置最后一块标志
        uint8_t flags = 0;
        if (is_last_chunk) {
            flags |= static_cast<uint8_t>(protocol::ProtocolFlags::LAST_CHUNK);
        }
        response_msg.set_flags(flags);
        
        // 已经设置了标志位，不需要再设置
        
        // 编码响应消息
        std::vector<uint8_t> response_buffer;
        
        // 如果启用了加密，则加密响应
        if (encryption_enabled_ && key_exchange_completed_) {
            // 首先编码不带加密标志的消息
            if (!response_msg.encode(response_buffer)) {
                LOG_ERROR("Session %zu: Failed to encode upload response", session_id_);
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
                LOG_ERROR("Session %zu: Failed to encode encrypted upload response", session_id_);
                return false;
            }
            
            LOG_DEBUG("Session %zu: Response encrypted successfully", session_id_);
        } else {
            // 不使用加密
            if (!response_msg.encode(response_buffer)) {
                LOG_ERROR("Session %zu: Failed to encode upload response", session_id_);
                return false;
            }
        }
        
        // 发送响应
        network::SocketError err = socket_->send_all(response_buffer.data(), response_buffer.size());
        if (err != network::SocketError::SUCCESS) {
            LOG_ERROR("Session %zu: Failed to send upload response: %d", session_id_, static_cast<int>(err));
            return false;
        }

        LOG_INFO("Session %zu: Upload chunk processed successfully for file %s", session_id_, filename.c_str());
        return true;
        
    } catch (const std::exception& e) {
        LOG_ERROR("Session %zu: Exception while handling upload: %s", session_id_, e.what());
        return false;
    }
}

bool ClientSession::handle_download(const std::vector<uint8_t>& buffer) {
    try {
        // 添加额外调试信息
        LOG_INFO("Session %zu: Received download message, buffer size: %zu", session_id_, buffer.size());
        
        // 解析下载消息
        protocol::Message msg;
        if (!msg.decode(buffer)) {
            LOG_ERROR("Session %zu: Failed to decode download message", session_id_);
            return false;
        }
        
        // 检查是否需要解密
        uint8_t flags_value = msg.get_flags();
        bool is_encrypted = (flags_value & static_cast<uint8_t>(protocol::ProtocolFlags::ENCRYPTED)) != 0;
        
        if (is_encrypted && encryption_enabled_ && key_exchange_completed_) {
            LOG_DEBUG("Session %zu: Message is encrypted, decrypting payload", session_id_);
            
            // 获取负载并解密
            const std::vector<uint8_t>& encrypted_payload = msg.get_payload();
            std::vector<uint8_t> decrypted_payload = decrypt_data(encrypted_payload);
            
            // 更新消息的负载
            msg.set_payload(decrypted_payload.data(), decrypted_payload.size());
            
            // 清除加密标志
            msg.set_flags(flags_value & ~static_cast<uint8_t>(protocol::ProtocolFlags::ENCRYPTED));
            
            LOG_DEBUG("Session %zu: Payload decrypted successfully, size: %zu -> %zu", 
                     session_id_, encrypted_payload.size(), decrypted_payload.size());
        } else if (is_encrypted) {
            LOG_WARNING("Session %zu: Message is encrypted but encryption is not ready", session_id_);
            return false;
        }
        
        protocol::DownloadMessage download_msg(msg);
        
        // 获取文件信息
        std::string filename = download_msg.get_filename();
        uint64_t offset = download_msg.get_offset();
        uint64_t length = download_msg.get_length();
        
        LOG_INFO("Session %zu: Received download request for file %s, offset: %llu, length: %llu",
                 session_id_, filename.c_str(), offset, length);
        
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
                 session_id_, storage_path.c_str(), file_path.c_str());
        
        // 检查文件是否存在
        if (!fs::exists(file_path)) {
            LOG_ERROR("Session %zu: File not found: %s", session_id_, file_path.c_str());
            
            // 发送错误响应
            protocol::Message error_response(protocol::OperationType::ERROR);
            std::string error_msg = "File not found: " + filename;
            error_response.set_payload(error_msg.data(), error_msg.size());
            
            std::vector<uint8_t> response_buffer;
            error_response.encode(response_buffer);
            
            socket_->send_all(response_buffer.data(), response_buffer.size());
            return false;
        }
        
        // 获取文件大小
        uint64_t file_size = fs::file_size(file_path);
        LOG_DEBUG("Session %zu: File size: %llu bytes", session_id_, file_size);
        
        // 打开文件
        std::ifstream file(file_path, std::ios::binary);
        if (!file.is_open()) {
            LOG_ERROR("Session %zu: Failed to open file for reading: %s", session_id_, file_path.c_str());
            return false;
        }
        
        // 设置读取位置
        file.seekg(offset);
        LOG_DEBUG("Session %zu: Seeking to offset %llu", session_id_, offset);
        
        // 计算分块大小，默认使用1MB的块大小
        const size_t chunk_size = 1024 * 1024;
        LOG_DEBUG("Session %zu: Using chunk size: %zu bytes", session_id_, chunk_size);
        
        // 如果指定了长度，则使用指定长度，否则从当前偏移量读取到文件末尾
        uint64_t remaining = (length > 0) ? length : (file_size - offset);
        uint64_t current_offset = offset;
        
        LOG_DEBUG("Session %zu: Will transfer %llu bytes total", session_id_, remaining);
        
        // 单独处理空文件或读取长度为0的情况
        if (file_size == 0 || remaining == 0) {
            LOG_WARNING("Session %zu: File is empty or requested length is 0", session_id_);
            
            // 创建下载响应消息，空数据
            protocol::DownloadMessage response_msg;
            response_msg.set_response_data(nullptr, 0, file_size, true);
            
            // 编码消息
            std::vector<uint8_t> response_buffer;
            if (!response_msg.encode(response_buffer)) {
                LOG_ERROR("Session %zu: Failed to encode empty download response", session_id_);
                return false;
            }
            
            // 发送响应
            LOG_DEBUG("Session %zu: Sending empty response with file_size=%llu", session_id_, file_size);
            network::SocketError err = socket_->send_all(response_buffer.data(), response_buffer.size());
            if (err != network::SocketError::SUCCESS) {
                LOG_ERROR("Session %zu: Failed to send empty download response: %d", 
                          session_id_, static_cast<int>(err));
                return false;
            }
            
            LOG_INFO("Session %zu: Sent empty file response for %s", session_id_, filename.c_str());
            file.close();
            return true;
        }
        
        size_t total_sent = 0;
        
        while (remaining > 0 && file.good()) {
            // 计算当前块大小
            size_t current_chunk_size = static_cast<size_t>(std::min(static_cast<uint64_t>(chunk_size), remaining));
            
            LOG_DEBUG("Session %zu: Reading chunk of size %zu at offset %llu", 
                      session_id_, current_chunk_size, current_offset);
            
            // 读取文件数据
            std::vector<uint8_t> file_data(current_chunk_size);
            file.read(reinterpret_cast<char*>(file_data.data()), current_chunk_size);
            
            // 实际读取的字节数
            size_t bytes_read = static_cast<size_t>(file.gcount());
            LOG_DEBUG("Session %zu: Actually read %zu bytes", session_id_, bytes_read);
            
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
                LOG_DEBUG("Session %zu: First bytes: %s", session_id_, data_preview.c_str());
            }
            
            // 创建下载响应消息
            protocol::DownloadMessage response_msg;
            response_msg.set_response_data(file_data.data(), file_data.size(), file_size, is_last_chunk);
            
            // 编码消息
            std::vector<uint8_t> response_buffer;
            
            // 如果启用了加密，则加密响应
            if (encryption_enabled_ && key_exchange_completed_) {
                // 首先编码不带加密标志的消息
                if (!response_msg.encode(response_buffer)) {
                    LOG_ERROR("Session %zu: Failed to encode download response", session_id_);
                    return false;
                }
                
                // 获取原始消息数据（跳过头部）
                std::vector<uint8_t> payload(response_buffer.begin() + sizeof(protocol::ProtocolHeader), 
                                           response_buffer.end());
                
                // 加密负载
                std::vector<uint8_t> encrypted_payload = encrypt_data(payload);
                
                // 创建新的带加密标志的消息
                protocol::Message encrypted_msg(protocol::OperationType::DOWNLOAD);
                encrypted_msg.set_flags(static_cast<uint8_t>(protocol::ProtocolFlags::ENCRYPTED) | 
                                      (is_last_chunk ? static_cast<uint8_t>(protocol::ProtocolFlags::LAST_CHUNK) : 0));
                
                // 直接设置负载，避免再添加元数据
                encrypted_msg.set_payload(encrypted_payload.data(), encrypted_payload.size());
                
                // 编码加密消息
                response_buffer.clear();
                if (!encrypted_msg.encode(response_buffer)) {
                    LOG_ERROR("Session %zu: Failed to encode encrypted download response", session_id_);
                    return false;
                }
                
                LOG_DEBUG("Session %zu: Response encrypted successfully", session_id_);
            } else {
                // 不使用加密
                if (!response_msg.encode(response_buffer)) {
                    LOG_ERROR("Session %zu: Failed to encode download response", session_id_);
                    return false;
                }
            }
            
            LOG_DEBUG("Session %zu: Sending response: data_size=%zu, buffer_size=%zu, is_last=%d, flags=%u", 
                     session_id_, file_data.size(), response_buffer.size(), is_last_chunk ? 1 : 0,
                     response_msg.get_flags());
            
            // 发送响应
            network::SocketError err = socket_->send_all(response_buffer.data(), response_buffer.size());
            if (err != network::SocketError::SUCCESS) {
                LOG_ERROR("Session %zu: Failed to send download response: %d", 
                          session_id_, static_cast<int>(err));
                return false;
            }
            
            LOG_DEBUG("Session %zu: Sent chunk for file %s, offset: %llu, size: %zu, is_last: %d",
                      session_id_, filename.c_str(), current_offset, bytes_read, is_last_chunk);
            
            // 更新偏移量和剩余字节数
            current_offset += bytes_read;
            remaining -= bytes_read;
            total_sent += bytes_read;
            
            // 如果读取的数据小于请求的块大小，说明已经到达文件末尾
            if (bytes_read < current_chunk_size) {
                LOG_DEBUG("Session %zu: Reached end of file or read less than requested", session_id_);
                break;
            }
        }
        
        file.close();
        
        LOG_INFO("Session %zu: Download completed for file %s, total sent: %zu bytes",
                 session_id_, filename.c_str(), total_sent);
        
        return true;
        
    } catch (const std::exception& e) {
        LOG_ERROR("Session %zu: Exception while handling download: %s", session_id_, e.what());
        return false;
    }
}

bool ClientSession::handle_key_exchange(const std::vector<uint8_t>& buffer) {
    try {
        LOG_INFO("Session %zu: Received key exchange message, buffer size: %zu", session_id_, buffer.size());
        
        // 解析密钥交换消息
        protocol::Message msg;
        if (!msg.decode(buffer)) {
            LOG_ERROR("Session %zu: Failed to decode key exchange message", session_id_);
            return false;
        }
        
        protocol::KeyExchangeMessage key_msg(msg);
        protocol::KeyExchangePhase phase = key_msg.get_exchange_phase();
        
        LOG_INFO("Session %zu: Key exchange phase: %d", session_id_, static_cast<int>(phase));
        
        if (phase == protocol::KeyExchangePhase::CLIENT_HELLO) {
            // 获取客户端参数
            std::vector<uint8_t> client_params = key_msg.get_exchange_params();
            if (client_params.empty()) {
                LOG_ERROR("Session %zu: Empty client key exchange params", session_id_);
                return false;
            }
            
            // 从客户端参数中提取DH参数
            if (client_params.size() < sizeof(uint32_t)) {
                LOG_ERROR("Session %zu: Invalid client params format", session_id_);
                return false;
            }
            
            // 读取p的长度和数据
            uint32_t p_size = 0;
            std::memcpy(&p_size, client_params.data(), sizeof(uint32_t));
            
            if (client_params.size() < sizeof(uint32_t) + p_size) {
                LOG_ERROR("Session %zu: Client params too short for p", session_id_);
                return false;
            }
            
            std::vector<uint8_t> p(client_params.begin() + sizeof(uint32_t), 
                                   client_params.begin() + sizeof(uint32_t) + p_size);
            
            // 读取g的长度和数据
            size_t g_offset = sizeof(uint32_t) + p_size;
            if (client_params.size() < g_offset + sizeof(uint32_t)) {
                LOG_ERROR("Session %zu: Client params too short for g length", session_id_);
                return false;
            }
            
            uint32_t g_size = 0;
            std::memcpy(&g_size, client_params.data() + g_offset, sizeof(uint32_t));
            
            if (client_params.size() < g_offset + sizeof(uint32_t) + g_size) {
                LOG_ERROR("Session %zu: Client params too short for g", session_id_);
                return false;
            }
            
            std::vector<uint8_t> g(client_params.begin() + g_offset + sizeof(uint32_t),
                                  client_params.begin() + g_offset + sizeof(uint32_t) + g_size);
            
            // 读取客户端公钥
            size_t pub_offset = g_offset + sizeof(uint32_t) + g_size;
            if (client_params.size() < pub_offset + sizeof(uint32_t)) {
                LOG_ERROR("Session %zu: Client params too short for public key length", session_id_);
                return false;
            }
            
            uint32_t pub_size = 0;
            std::memcpy(&pub_size, client_params.data() + pub_offset, sizeof(uint32_t));
            
            if (client_params.size() < pub_offset + sizeof(uint32_t) + pub_size) {
                LOG_ERROR("Session %zu: Client params too short for public key", session_id_);
                return false;
            }
            
            std::vector<uint8_t> client_public_key(
                client_params.begin() + pub_offset + sizeof(uint32_t),
                client_params.begin() + pub_offset + sizeof(uint32_t) + pub_size);
            
            // 构建客户端DH参数
            utils::DHParams client_dh_params;
            client_dh_params.p = p;
            client_dh_params.g = g;
            client_dh_params.public_key = client_public_key;
            
            LOG_INFO("Session %zu: Extracted DH params - p: %zu bytes, g: %zu bytes, client public key: %zu bytes",
                     session_id_, p.size(), g.size(), client_public_key.size());
            
            // 使用客户端参数创建服务器DH密钥对
            dh_private_key_.clear();
            
            // 创建DH上下文
            DH* dh = DH_new();
            if (!dh) {
                LOG_ERROR("Session %zu: Failed to create DH context", session_id_);
                return false;
            }
            
            // 设置p和g参数
            BIGNUM* bn_p = BN_bin2bn(p.data(), p.size(), nullptr);
            BIGNUM* bn_g = BN_bin2bn(g.data(), g.size(), nullptr);
            
            if (!bn_p || !bn_g) {
                LOG_ERROR("Session %zu: Failed to convert p or g to BIGNUM", session_id_);
                if (bn_p) BN_free(bn_p);
                if (bn_g) BN_free(bn_g);
                DH_free(dh);
                return false;
            }
            
            if (DH_set0_pqg(dh, bn_p, nullptr, bn_g) != 1) {
                LOG_ERROR("Session %zu: Failed to set DH parameters", session_id_);
                BN_free(bn_p);
                BN_free(bn_g);
                DH_free(dh);
                return false;
            }
            
            // 生成密钥对
            if (DH_generate_key(dh) != 1) {
                LOG_ERROR("Session %zu: Failed to generate DH key pair", session_id_);
                DH_free(dh);
                return false;
            }
            
            // 获取私钥和公钥
            const BIGNUM* priv_key = DH_get0_priv_key(dh);
            const BIGNUM* pub_key = DH_get0_pub_key(dh);
            
            if (!priv_key || !pub_key) {
                LOG_ERROR("Session %zu: Failed to get DH keys", session_id_);
                DH_free(dh);
                return false;
            }
            
            // 将私钥保存到成员变量
            dh_private_key_.resize(BN_num_bytes(priv_key));
            BN_bn2bin(priv_key, dh_private_key_.data());
            
            // 获取服务器公钥
            std::vector<uint8_t> server_public_key(BN_num_bytes(pub_key));
            BN_bn2bin(pub_key, server_public_key.data());
            
            // 计算共享密钥
            std::vector<uint8_t> shared_key = utils::Encryption::compute_dh_shared_key(
                client_dh_params, dh_private_key_);
            
            if (shared_key.empty()) {
                LOG_ERROR("Session %zu: Failed to compute shared key", session_id_);
                DH_free(dh);
                return false;
            }
            
            // 派生AES密钥和IV
            utils::Encryption::derive_key_and_iv(shared_key, encryption_key_, encryption_iv_);
            
            if (encryption_key_.size() != 32 || encryption_iv_.size() != 16) {
                LOG_ERROR("Session %zu: Invalid derived key or IV size: key=%zu, iv=%zu", 
                          session_id_, encryption_key_.size(), encryption_iv_.size());
                DH_free(dh);
                return false;
            }
            
            // 准备服务器响应
            protocol::KeyExchangeMessage server_hello(protocol::KeyExchangePhase::SERVER_HELLO);
            
            // 序列化服务器公钥
            std::vector<uint8_t> server_params;
            uint32_t server_key_size = server_public_key.size();
            
            // 写入服务器公钥长度
            server_params.resize(sizeof(uint32_t));
            std::memcpy(server_params.data(), &server_key_size, sizeof(uint32_t));
            
            // 写入服务器公钥
            server_params.insert(server_params.end(), 
                                server_public_key.begin(), 
                                server_public_key.end());
            
            server_hello.set_exchange_params(server_params);
            
            // 编码响应消息
            std::vector<uint8_t> response_buffer;
            if (!server_hello.encode(response_buffer)) {
                LOG_ERROR("Session %zu: Failed to encode server hello message", session_id_);
                DH_free(dh);
                return false;
            }
            
            // 发送响应
            network::SocketError err = socket_->send_all(response_buffer.data(), response_buffer.size());
            if (err != network::SocketError::SUCCESS) {
                LOG_ERROR("Session %zu: Failed to send server hello: %d", session_id_, static_cast<int>(err));
                DH_free(dh);
                return false;
            }
            
            // 清理DH上下文
            DH_free(dh);
            
            // 启用加密
            encryption_enabled_ = true;
            key_exchange_completed_ = true;
            
            LOG_INFO("Session %zu: Key exchange completed successfully", session_id_);
            return true;
        } else {
            LOG_ERROR("Session %zu: Unexpected key exchange phase: %d", 
                      session_id_, static_cast<int>(phase));
            return false;
        }
    } catch (const std::exception& e) {
        LOG_ERROR("Session %zu: Exception during key exchange: %s", session_id_, e.what());
        return false;
    }
}

// 实现加密和解密方法
std::vector<uint8_t> ClientSession::encrypt_data(const std::vector<uint8_t>& data) {
    if (!encryption_enabled_ || !key_exchange_completed_ || data.empty()) {
        return data;
    }
    
    return utils::Encryption::aes_encrypt(data, encryption_key_, encryption_iv_);
}

std::vector<uint8_t> ClientSession::decrypt_data(const std::vector<uint8_t>& data) {
    if (!encryption_enabled_ || !key_exchange_completed_ || data.empty()) {
        return data;
    }
    
    return utils::Encryption::aes_decrypt(data, encryption_key_, encryption_iv_);
}

// ServerCore实现
ServerCore::ServerCore()
    : config_(),
      listen_socket_(nullptr),
      accept_thread_(),
      session_manager_thread_(),
      running_(false),
      sessions_(),
      sessions_mutex_(),
      stop_cv_(),
      stop_mutex_() {
}

ServerCore::~ServerCore() {
    stop();
}

bool ServerCore::initialize(const ServerConfig& config, utils::LogLevel log_level) {
    config_ = config;
    
    // 初始化日志
    utils::Logger::instance().init(log_level);
    
    // 设置静态存储路径
    storage_path_ = config.storage_path;
    
    LOG_INFO("Server initializing with configuration:");
    LOG_INFO("  Listen: %s:%d", config_.bind_address.c_str(), config_.port);
    LOG_INFO("  Storage path: %s", config_.storage_path.c_str());
    LOG_INFO("  Max connections: %d", config_.max_connections);
    LOG_INFO("  Thread pool size: %d", config_.thread_pool_size);
    
    // 确保存储目录存在
    fs::path storage_dir(config_.storage_path);
    try {
        if (!fs::exists(storage_dir)) {
            LOG_INFO("Creating storage directory: %s", config_.storage_path.c_str());
            fs::create_directories(storage_dir);
        }
    } catch (const std::exception& e) {
        LOG_ERROR("Failed to create storage directory: %s", e.what());
        return false;
    }
    
    // 创建监听socket
    listen_socket_ = std::make_unique<network::TcpSocket>();
    
    // 绑定地址和端口
    network::SocketError err = listen_socket_->bind(config_.bind_address, config_.port);
    if (err != network::SocketError::SUCCESS) {
        LOG_ERROR("Failed to bind socket: %d", static_cast<int>(err));
        return false;
    }
    
    // 开始监听
    err = listen_socket_->listen(10);
    if (err != network::SocketError::SUCCESS) {
        LOG_ERROR("Failed to listen: %d", static_cast<int>(err));
        return false;
    }
    
    LOG_INFO("Server initialized successfully");
    return true;
}

bool ServerCore::start() {
    if (running_) {
        LOG_WARNING("Server already running");
        return true;
    }
    
    // 检查socket是否已经初始化，如果没有，则创建
    if (!listen_socket_ || listen_socket_->get_fd() < 0) {
        // 创建监听socket
        listen_socket_ = std::make_unique<network::TcpSocket>();
        
        // 绑定地址和端口
        LOG_INFO("Binding to %s:%d...", config_.bind_address.c_str(), config_.port);
        network::SocketError err = listen_socket_->bind(config_.bind_address, config_.port);
        if (err != network::SocketError::SUCCESS) {
            LOG_ERROR("Failed to bind socket: %d", static_cast<int>(err));
            return false;
        }
        
        // 开始监听
        err = listen_socket_->listen(10);
        if (err != network::SocketError::SUCCESS) {
            LOG_ERROR("Failed to listen: %d", static_cast<int>(err));
            return false;
        }
    }
    
    // 启动服务器
    running_ = true;
    
    // 启动接受连接线程
    LOG_DEBUG("Starting accept thread...");
    accept_thread_ = std::thread(&ServerCore::accept_thread, this);
    
    // 启动会话管理线程
    LOG_DEBUG("Starting session manager thread...");
    session_manager_thread_ = std::thread(&ServerCore::session_manager_thread, this);
    
    LOG_INFO("Server started, listening on %s:%d", config_.bind_address.c_str(), config_.port);
    return true;
}

void ServerCore::stop() {
    if (!running_) {
        return;
    }
    
    LOG_INFO("Stopping server...");
    
    {
        std::lock_guard<std::mutex> lock(stop_mutex_);
        running_ = false;
    }
    
    // 关闭监听socket，这将使accept线程退出阻塞
    if (listen_socket_) {
        listen_socket_->close();
    }
    
    // 停止所有会话
    {
        std::lock_guard<std::mutex> lock(sessions_mutex_);
        for (auto& session : sessions_) {
            try {
                if (session) {
                    session->stop();
                }
            } catch (const std::exception& e) {
                LOG_ERROR("Exception while stopping session: %s", e.what());
            }
        }
    }
    
    stop_cv_.notify_all();
    
    LOG_INFO("Server stopped");
}

bool ServerCore::is_running() const {
    return running_;
}

void ServerCore::wait() {
    // 等待服务器停止
    std::unique_lock<std::mutex> lock(stop_mutex_);
    stop_cv_.wait(lock, [this] { return !running_; });
    
    // 等待线程结束
    if (accept_thread_.joinable()) {
        LOG_DEBUG("Waiting for accept thread to finish...");
        accept_thread_.join();
    }
    
    if (session_manager_thread_.joinable()) {
        LOG_DEBUG("Waiting for session manager thread to finish...");
        session_manager_thread_.join();
    }
    
    LOG_INFO("All server threads stopped");
}

void ServerCore::accept_thread() {
    LOG_INFO("Accept thread started");
    
    int consecutive_errors = 0;
    const int max_consecutive_errors = 10;  // 允许的最大连续错误数
    
    while (running_) {
        try {
            // 检查是否超过最大连接数
            {
                std::lock_guard<std::mutex> lock(sessions_mutex_);
                if (sessions_.size() >= static_cast<size_t>(config_.max_connections)) {
                    LOG_WARNING("Reached maximum connections: %d, waiting...", config_.max_connections);
                    std::this_thread::sleep_for(std::chrono::seconds(1));
                    continue;
                }
            }
            
            // 接受连接
            network::TcpSocket client_socket;
            network::SocketError err = listen_socket_->accept(client_socket);
            if (err != network::SocketError::SUCCESS) {
                if (err == network::SocketError::TIMEOUT) {
                    // 超时是正常的，继续尝试
                    std::this_thread::sleep_for(std::chrono::milliseconds(10));
                    continue;
                }
                
                // 其他错误，记录并重试
                LOG_ERROR("Failed to accept connection: %d", static_cast<int>(err));
                consecutive_errors++;
                
                if (consecutive_errors >= max_consecutive_errors) {
                    LOG_ERROR("Too many consecutive accept errors, restarting listener...");
                    // 尝试重新启动监听
                    listen_socket_->close();
                    std::this_thread::sleep_for(std::chrono::seconds(1));
                    
                    // 重新创建并绑定监听socket
                    listen_socket_ = std::make_unique<network::TcpSocket>();
                    err = listen_socket_->bind(config_.bind_address, config_.port);
                    if (err != network::SocketError::SUCCESS) {
                        LOG_ERROR("Failed to bind socket during recovery: %d", static_cast<int>(err));
                        std::this_thread::sleep_for(std::chrono::seconds(5));
                        continue;
                    }
                    
                    err = listen_socket_->listen(10);
                    if (err != network::SocketError::SUCCESS) {
                        LOG_ERROR("Failed to listen socket during recovery: %d", static_cast<int>(err));
                        std::this_thread::sleep_for(std::chrono::seconds(5));
                        continue;
                    }
                    
                    // 重置错误计数
                    consecutive_errors = 0;
                    LOG_INFO("Listener restarted successfully");
                }
                
                std::this_thread::sleep_for(std::chrono::milliseconds(100));
                continue;
            }
            
            // 重置错误计数
            consecutive_errors = 0;
            
            // 成功接受连接
            LOG_INFO("Accepted connection from %s:%d", 
                   client_socket.get_remote_address().c_str(), 
                   client_socket.get_remote_port());
            
            // 记录客户端socket信息，用于调试
            LOG_DEBUG("Client socket details - fd=%d, local=%s:%d, remote=%s:%d", 
                     client_socket.get_fd(),
                     client_socket.get_local_address().c_str(),
                     client_socket.get_local_port(),
                     client_socket.get_remote_address().c_str(), 
                     client_socket.get_remote_port());
            
            // 确保连接状态正确
            if (!client_socket.is_connected()) {
                LOG_WARNING("Socket reported as not connected after accept, skipping");
                continue;
            }
            
            // 创建一个新的socket转移所有权，避免使用client_socket.get_fd()
            std::unique_ptr<network::TcpSocket> socket_ptr = std::make_unique<network::TcpSocket>(std::move(client_socket));
            
            // 记录socket_ptr的当前状态
            LOG_DEBUG("Socket after moving to unique_ptr - fd=%d, connected=%d, remote=%s:%d", 
                     socket_ptr->get_fd(),
                     socket_ptr->is_connected() ? 1 : 0,
                     socket_ptr->get_remote_address().c_str(), 
                     socket_ptr->get_remote_port());
            
            // 再次验证转移后的socket
            if (!socket_ptr || !socket_ptr->is_connected()) {
                LOG_ERROR("Socket lost connection during ownership transfer to unique_ptr, skipping");
                continue;
            }
            
            // 验证socket_ptr有效性
            int socket_fd = socket_ptr->get_fd();
            if (socket_fd < 0) {
                LOG_ERROR("Invalid socket file descriptor after move: %d", socket_fd);
                continue;
            }
            
            // 创建客户端会话并启动
            LOG_DEBUG("Creating ClientSession with socket_ptr - fd=%d", socket_fd);
            std::shared_ptr<ClientSession> session = std::make_shared<ClientSession>(std::move(socket_ptr));
            
            // 检查session的socket现在是否还有效 - 这只是记录日志，无法直接访问内部socket
            LOG_DEBUG("Created ClientSession - id=%zu, client=%s", 
                     session->get_session_id(), 
                     session->get_client_address().c_str());
            
            {
                std::lock_guard<std::mutex> lock(sessions_mutex_);
                sessions_.push_back(session);
                LOG_INFO("Added new session, current sessions: %zu", sessions_.size());
            }
            
            // 启动会话线程
            LOG_DEBUG("Starting session %zu", session->get_session_id());
            session->start();
            
        } catch (const std::exception& e) {
            LOG_ERROR("Exception in accept thread: %s", e.what());
            std::this_thread::sleep_for(std::chrono::seconds(1));
        }
    }
    
    LOG_INFO("Accept thread exiting");
}

void ServerCore::session_manager_thread() {
    LOG_INFO("Session manager thread started");
    
    while (running_) {
        try {
            // 定时检查会话状态
            std::this_thread::sleep_for(std::chrono::seconds(5));
            
            std::vector<std::shared_ptr<ClientSession>> active_sessions;
            
            {
                std::lock_guard<std::mutex> lock(sessions_mutex_);
                
                // 筛选出活跃的会话
                for (const auto& session : sessions_) {
                    if (session && session->is_connected()) {
                        active_sessions.push_back(session);
                    }
                }
                
                // 如果有会话被移除，则更新会话列表
                if (active_sessions.size() != sessions_.size()) {
                    LOG_INFO("Removed %zu inactive sessions", sessions_.size() - active_sessions.size());
                    sessions_ = active_sessions;
                }
                
                LOG_DEBUG("Current active sessions: %zu", sessions_.size());
            }
            
        } catch (const std::exception& e) {
            LOG_ERROR("Exception in session manager thread: %s", e.what());
            std::this_thread::sleep_for(std::chrono::seconds(1));
        }
    }
    
    LOG_INFO("Session manager thread exiting");
    
    // 停止所有会话
    {
        std::lock_guard<std::mutex> lock(sessions_mutex_);
        for (auto& session : sessions_) {
            if (session) {
                try {
                    session->stop();
                } catch (const std::exception& e) {
                    LOG_ERROR("Exception while stopping session: %s", e.what());
                }
            }
        }
        sessions_.clear();
    }
}

// 静态成员初始化
std::string ServerCore::storage_path_;

} // namespace server
} // namespace ft 