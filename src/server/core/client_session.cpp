#include "client_session.h"
#include "../handlers/upload_handler.h"
#include "../handlers/download_handler.h"
#include "../handlers/key_exchange_handler.h"
#include "../../common/protocol/protocol.h"
#include "../../common/utils/crypto/encryption.h"
#include <thread>
#include <chrono>
#include <cstring>

namespace ft {
namespace server {

// ClientSession静态成员初始化
std::atomic<size_t> ClientSession::next_session_id_(1);

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
    
    // 创建协议处理器
    upload_handler_ = std::make_unique<UploadHandler>(*this);
    download_handler_ = std::make_unique<DownloadHandler>(*this);
    key_exchange_handler_ = std::make_unique<KeyExchangeHandler>(*this);
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
    if (!running_) {
        return;  // 避免重复停止
    }
    
    // 首先设置运行标志，避免重入问题
    running_ = false;
    
    // 关闭套接字，这会导致阻塞在recv/send的线程返回错误
    if (socket_) {
        socket_->close();
        socket_.reset();  // 释放套接字资源
    }
    
    // 等待工作线程结束 - 使用直接join，避免复杂的线程管理
    if (thread_.joinable()) {
        thread_.join();
    }
    
    // 清理加密相关资源
    encryption_key_.clear();
    encryption_iv_.clear();
    dh_private_key_.clear();
    
    LOG_INFO("Session %zu: Stopped", session_id_);
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

network::TcpSocket& ClientSession::get_socket() {
    return *socket_;
}

bool ClientSession::is_encryption_enabled() const {
    return encryption_enabled_;
}

bool ClientSession::is_key_exchange_completed() const {
    return key_exchange_completed_;
}

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

void ClientSession::set_encryption_params(const std::vector<uint8_t>& encryption_key,
                                         const std::vector<uint8_t>& encryption_iv,
                                         const std::vector<uint8_t>& dh_private_key) {
    encryption_key_ = encryption_key;
    encryption_iv_ = encryption_iv;
    dh_private_key_ = dh_private_key;
}

void ClientSession::enable_encryption() {
    encryption_enabled_ = true;
    key_exchange_completed_ = true;
}

void ClientSession::process() {
    // 连接握手
    LOG_INFO("Session %zu: Started for client %s", session_id_, get_client_address().c_str());
    
    // 首先检查客户端是否还连接
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
        
        network::SocketError err = socket_->recv_all(header_buffer.data(), header_buffer.size());
        if (err != network::SocketError::SUCCESS) {
            consecutive_errors++;
            if (consecutive_errors >= max_consecutive_errors) {
                LOG_ERROR("Session %zu: Too many consecutive errors (%d), terminating session", 
                         session_id_, consecutive_errors);
                break;
            }
            
            if (running_) {
                LOG_WARNING("Session %zu: Failed to receive header (error %d), consecutive errors: %d/%d", 
                           session_id_, static_cast<int>(err), consecutive_errors, max_consecutive_errors);
                std::this_thread::sleep_for(std::chrono::milliseconds(100));
            }
            continue;
        }
        
        // 重置连续错误计数
        consecutive_errors = 0;
        
        // 解析协议头
        protocol::ProtocolHeader* header = reinterpret_cast<protocol::ProtocolHeader*>(header_buffer.data());
        
        // 验证魔数
        uint32_t magic_value = header->magic;
        if (magic_value != protocol::PROTOCOL_MAGIC) {
            LOG_ERROR("Session %zu: Invalid protocol magic: 0x%08x", session_id_, magic_value);
            continue;
        }
        
        // 获取消息类型和长度
        protocol::OperationType op_type = static_cast<protocol::OperationType>(header->type);
        uint32_t payload_length = header->length;
        
        LOG_DEBUG("Session %zu: Received header - type: %d, length: %u", 
                 session_id_, static_cast<int>(op_type), payload_length);
        
        // 接收完整消息
        std::vector<uint8_t> full_message = header_buffer;
        if (payload_length > 0) {
            std::vector<uint8_t> payload_buffer(payload_length);
            err = socket_->recv_all(payload_buffer.data(), payload_buffer.size());
            if (err != network::SocketError::SUCCESS) {
                LOG_ERROR("Session %zu: Failed to receive payload: %d", session_id_, static_cast<int>(err));
                continue;
            }
            
            full_message.insert(full_message.end(), payload_buffer.begin(), payload_buffer.end());
        }
        
        // 根据消息类型分发到相应的处理器
        bool handled = false;
        switch (op_type) {
            case protocol::OperationType::UPLOAD:
                handled = upload_handler_->handle(full_message);
                break;
                
            case protocol::OperationType::DOWNLOAD:
                handled = download_handler_->handle(full_message);
                break;
                
            case protocol::OperationType::KEY_EXCHANGE:
                handled = key_exchange_handler_->handle(full_message);
                break;
                
            case protocol::OperationType::HEARTBEAT:
                handled = handle_heartbeat_response(full_message);
                break;
                
            default:
                LOG_WARNING("Session %zu: Unknown operation type: %d", 
                           session_id_, static_cast<int>(op_type));
                handled = false;
                break;
        }
        
        if (!handled) {
            LOG_WARNING("Session %zu: Failed to handle message of type %d", 
                       session_id_, static_cast<int>(op_type));
        }
    }
    
    LOG_INFO("Session %zu: Processing thread exiting", session_id_);
}

bool ClientSession::handle_heartbeat_response(const std::vector<uint8_t>& /*buffer*/) {
    // 发送心跳响应
    LOG_DEBUG("Session %zu: Received heartbeat, preparing response", session_id_);
    
    // 创建新的心跳响应消息
    protocol::Message response(protocol::OperationType::HEARTBEAT);
    std::vector<uint8_t> response_buffer;
    if (!response.encode(response_buffer)) {
        LOG_ERROR("Session %zu: Failed to encode heartbeat response", session_id_);
        return false;
    }
    
    // 添加详细调试信息
    LOG_DEBUG("Session %zu: Heartbeat response encoded, size: %zu bytes", 
             session_id_, response_buffer.size());
    
    // 检查和验证心跳响应头部
    if (response_buffer.size() < sizeof(protocol::ProtocolHeader)) {
        LOG_ERROR("Session %zu: Response buffer too small: %zu bytes", 
                  session_id_, response_buffer.size());
        return false;
    }
    
    // 发送心跳响应
    try {
        network::SocketError err = socket_->send_all(response_buffer.data(), response_buffer.size());
        if (err != network::SocketError::SUCCESS) {
            LOG_ERROR("Session %zu: Failed to send heartbeat response: %d", 
                     session_id_, static_cast<int>(err));
            return false;
        }
        
        LOG_DEBUG("Session %zu: Heartbeat response sent successfully", session_id_);
        return true;
    } catch (const std::exception& e) {
        LOG_ERROR("Session %zu: Exception while sending heartbeat response: %s", 
                 session_id_, e.what());
        return false;
    }
}

} // namespace server
} // namespace ft 