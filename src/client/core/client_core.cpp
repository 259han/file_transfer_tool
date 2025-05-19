#include "client_core.h"
#include "../../common/protocol/messages/upload_message.h"
#include "../../common/protocol/messages/download_message.h"
#include "../../common/protocol/messages/key_exchange_message.h"
#include "../../common/utils/crypto/encryption.h"
#include <chrono>
#include <fstream>
#include <filesystem>
#include <thread>
#include <cstring>
#include <netinet/tcp.h>  // 用于TCP_KEEPIDLE等参数

namespace fs = std::filesystem;

namespace ft {
namespace client {

ClientCore::ClientCore()
    : server_info_(),
      socket_(nullptr),
      progress_callback_(nullptr),
      is_connected_(false),
      heartbeat_thread_(),
      stop_heartbeat_(false),
      encryption_enabled_(false),
      encryption_key_(),
      encryption_iv_(),
      dh_private_key_(),
      key_exchange_completed_(false) {
}

ClientCore::~ClientCore() {
    disconnect();
}

bool ClientCore::initialize(utils::LogLevel log_level) {
    // 初始化日志
    utils::Logger::instance().init(log_level);
    
    LOG_INFO("Client initialized with log level: %d", static_cast<int>(log_level));
    return true;
}

bool ClientCore::enable_encryption() {
    encryption_enabled_ = true;
    
    // 在连接状态下需要进行密钥交换
    if (is_connected_) {
        if (!perform_key_exchange()) {
            LOG_ERROR("Failed to perform key exchange, disabling encryption");
            encryption_enabled_ = false;
            key_exchange_completed_ = false;
            return false;
        }
    } else {
        // 未连接状态下仅设置标志位
        key_exchange_completed_ = false;
    }
    
    LOG_INFO("Encryption enabled with AES-256-CBC");
    return true;
}

bool ClientCore::disable_encryption() {
    encryption_enabled_ = false;
    encryption_key_.clear();
    encryption_iv_.clear();
    
    LOG_INFO("Encryption disabled");
    return true;
}

bool ClientCore::is_encryption_enabled() const {
    return encryption_enabled_;
}

bool ClientCore::connect(const ServerInfo& server) {
    try {
        // 断开现有连接
        if (is_connected_) {
            disconnect();
        }
        
        // 创建Socket
        network::SocketOptions options;
        options.connect_timeout = std::chrono::milliseconds(10000);
        options.recv_timeout = std::chrono::milliseconds(5000);  // 接收超时
        options.send_timeout = std::chrono::milliseconds(5000);  // 发送超时
        options.keep_alive = true;                              // 启用保活
        options.recv_buffer_size = 256 * 1024;                  // 接收缓冲区
        options.send_buffer_size = 256 * 1024;                  // 发送缓冲区
        
        LOG_INFO("Creating new socket connection to %s:%d", server.host.c_str(), server.port);
        socket_ = std::make_unique<network::TcpSocket>(options);

        LOG_INFO("Connecting to server %s:%d", server.host.c_str(), server.port);
        
        int connect_retry = 0;
        const int max_connect_retries = 2;
        bool connect_success = false;
        
        while (connect_retry <= max_connect_retries && !connect_success) {
            network::SocketError err = socket_->connect(server.host, server.port);
            if (err == network::SocketError::SUCCESS) {
                connect_success = true;
                LOG_INFO("Connected to server %s:%d", server.host.c_str(), server.port);
            } else {
                if (connect_retry < max_connect_retries) {
                    connect_retry++;
                    LOG_WARNING("Connection failed, retrying %d/%d in 1 second...", 
                               connect_retry, max_connect_retries);
                    std::this_thread::sleep_for(std::chrono::seconds(1));
                    
                    // 重新创建socket
                    socket_ = std::make_unique<network::TcpSocket>(options);
                } else {
                    LOG_ERROR("Failed to connect to server: %d", static_cast<int>(err));
                    return false;
                }
            }
        }
        
        // 确认连接是否稳定
        if (!socket_ || !socket_->is_connected()) {
            LOG_ERROR("Socket connection not stable after establishment");
            if (socket_) {
                socket_->close();
            }
            return false;
        }
        
        // 连接后等待，确保服务器准备好接收
        LOG_INFO("Waiting for server readiness after connection...");
        bool connection_stable = true;
        
        // 将500ms的单次等待改为分段检查，每200ms检查一次，总共等待1200ms
        for (int i = 0; i < 6; i++) {  // 总共1200ms，每200ms检查一次连接状态
            if (!socket_ || !socket_->is_connected()) {
                LOG_ERROR("Connection lost during initial wait");
                connection_stable = false;
                break;
            }
            std::this_thread::sleep_for(std::chrono::milliseconds(200));
        }
        
        if (!connection_stable) {
            if (socket_) {
                socket_->close();
            }
            is_connected_ = false;
            return false;
        }
        
        LOG_INFO("Waited 1200ms after connection to ensure server readiness");
        
        // 再次验证连接状态
        if (!socket_ || !socket_->is_connected()) {
            LOG_ERROR("Connection lost during initial wait");
            is_connected_ = false;
            return false;
        }
        
        // 标记为已连接
        is_connected_ = true;
        server_info_ = server;
        
        // 如果加密已启用，执行密钥交换
        if (encryption_enabled_) {
            LOG_INFO("Encryption is enabled, performing key exchange");
            if (!perform_key_exchange()) {
                LOG_ERROR("Failed to perform key exchange during connection");
                is_connected_ = false;
                socket_->close();
                return false;
            }
        }
        
        // 发送初始心跳
        int heartbeat_retry = 0;
        const int max_heartbeat_retries = 8;  // 增加重试次数
        bool heartbeat_success = false;
        
        LOG_INFO("Attempting to establish initial heartbeat sequence");
        
        while (heartbeat_retry < max_heartbeat_retries && !heartbeat_success) {
            LOG_INFO("Sending initial heartbeat (attempt %d/%d)", 
                    heartbeat_retry + 1, max_heartbeat_retries);
            
            // 验证连接状态
            if (!socket_ || !socket_->is_connected()) {
                LOG_ERROR("Socket connection lost before heartbeat");
                is_connected_ = false;
                return false;
            }
            
            // 创建心跳消息并确保正确编码
            protocol::Message heartbeat_msg(protocol::OperationType::HEARTBEAT);
            std::vector<uint8_t> msg_buffer;
            bool encode_success = heartbeat_msg.encode(msg_buffer);
            
            if (!encode_success || msg_buffer.empty()) {
                LOG_ERROR("Failed to encode heartbeat message or empty buffer");
                is_connected_ = false;
                return false;
            }
            
            // 检查编码后的消息头
            if (msg_buffer.size() >= sizeof(protocol::ProtocolHeader)) {
                protocol::ProtocolHeader* header = reinterpret_cast<protocol::ProtocolHeader*>(msg_buffer.data());
                
                // 复制packed结构体字段到本地变量
                uint32_t magic = header->magic;
                uint8_t type = header->type;
                uint32_t length = header->length;
                
                LOG_DEBUG("Encoded heartbeat message header - magic: 0x%08x, type: %d, length: %u", 
                         magic, type, length);
                         
                if (magic != protocol::PROTOCOL_MAGIC) {
                    LOG_ERROR("Invalid magic in heartbeat message: 0x%08x", magic);
                    is_connected_ = false;
                    return false;
                }
                
                if (type != static_cast<uint8_t>(protocol::OperationType::HEARTBEAT)) {
                    LOG_ERROR("Invalid type in heartbeat message: %d", type);
                    is_connected_ = false;
                    return false;
                }
            } else {
                LOG_ERROR("Heartbeat message buffer too small: %zu bytes", msg_buffer.size());
                is_connected_ = false;
                return false;
            }
            
            // 发送心跳
            heartbeat_success = send_heartbeat();
            
            // 再次检查连接状态
            if (!socket_ || !socket_->is_connected()) {
                LOG_ERROR("Socket connection lost during heartbeat");
                is_connected_ = false;
                return false;
            }
            
            if (!heartbeat_success) {
                heartbeat_retry++;
                
                if (heartbeat_retry < max_heartbeat_retries) {
                    // 重试延迟随着尝试次数增加延迟也增加
                    int retry_delay = 500 + heartbeat_retry * 200;  // 从500ms到2100ms
                    LOG_WARNING("Initial heartbeat failed, retrying in %d ms...", retry_delay);
                    
                    // 分段检查连接状态，避免长时间阻塞
                    bool still_connected = true;
                    for (int i = 0; i < retry_delay / 100; i++) {
                        if (!socket_ || !socket_->is_connected()) {
                            LOG_ERROR("Socket connection lost during heartbeat retry wait");
                            is_connected_ = false;
                            still_connected = false;
                            break;
                        }
                        std::this_thread::sleep_for(std::chrono::milliseconds(100));
                    }
                    
                    if (!still_connected) {
                        return false;
                    }
                } else {
                    LOG_ERROR("Failed to send initial heartbeat after %d attempts", max_heartbeat_retries);
                    is_connected_ = false;
                    socket_->close();
                    return false;
                }
            }
        }
        
        if (!heartbeat_success) {
            LOG_ERROR("Initial heartbeat failed");
            is_connected_ = false;
            return false;
        }
        
        LOG_INFO("Initial heartbeat successful, connection established");
        
        // 启动心跳线程
        start_heartbeat_thread();
        
        return true;
        
    } catch (const std::exception& e) {
        LOG_ERROR("Exception during connect: %s", e.what());
        is_connected_ = false;
        if (socket_) {
            socket_->close();
        }
        return false;
    }
}

void ClientCore::start_heartbeat_thread() {
    stop_heartbeat_ = false;
    heartbeat_thread_ = std::thread([this]() {
        LOG_INFO("Heartbeat thread started");
        
        int consecutive_failures = 0;
        const int max_consecutive_failures = 5;  // 增加允许的连续失败次数
        
        while (!stop_heartbeat_ && is_connected_) {
            // 每15秒发送一次心跳，调整为更合理的间隔时间
            std::this_thread::sleep_for(std::chrono::seconds(15));
            
            if (stop_heartbeat_ || !is_connected_) {
                break;
            }
            
            // 每次心跳前检查连接状态
            if (!socket_ || !socket_->is_connected()) {
                LOG_WARNING("Socket disconnected before sending heartbeat");
                is_connected_ = false;
                break;
            }
            
            LOG_DEBUG("Sending periodic heartbeat");
            if (!send_heartbeat()) {
                consecutive_failures++;
                LOG_WARNING("Heartbeat failed (%d/%d consecutive failures)", 
                           consecutive_failures, max_consecutive_failures);
                
                // 连续失败后进行渐进式延迟重试
                if (consecutive_failures < max_consecutive_failures) {
                    // 计算重试延迟，随着失败次数增加延迟也增加
                    int retry_delay = std::min(5, consecutive_failures) * 1000;
                    LOG_INFO("Will retry heartbeat in %d ms", retry_delay);
                    
                    // 分段检查，避免长时间阻塞
                    for (int i = 0; i < retry_delay / 200 && !stop_heartbeat_ && is_connected_; i++) {
                        // 检查连接是否仍然有效
                        if (!socket_ || !socket_->is_connected()) {
                            LOG_WARNING("Socket disconnected during heartbeat retry delay");
                            is_connected_ = false;
                            break;
                        }
                        std::this_thread::sleep_for(std::chrono::milliseconds(200));
                    }
                    
                    // 如果分段检查期间未发现问题，立即重试一次心跳
                    if (is_connected_ && !stop_heartbeat_) {
                        LOG_INFO("Retrying heartbeat after delay");
                        if (send_heartbeat()) {
                            LOG_INFO("Heartbeat retry succeeded");
                            consecutive_failures = 0;  // 立即重置失败计数
                        }
                    }
                }
                
                // 只有连续失败多次才考虑断开连接
                if (consecutive_failures >= max_consecutive_failures) {
                    LOG_ERROR("Too many consecutive heartbeat failures, connection may be lost");
                    // 不立即断开，让下一次操作时再检查连接状态
                    // 但标记连接状态为可能断开
                    is_connected_ = false;
                    break;
                }
            } else {
                // 心跳成功，重置失败计数
                if (consecutive_failures > 0) {
                    LOG_INFO("Heartbeat succeeded after %d failures", consecutive_failures);
                    consecutive_failures = 0;
                }
            }
        }
        
        LOG_INFO("Heartbeat thread stopped");
    });
}

bool ClientCore::send_heartbeat() {
    if (!is_connected_) {
        LOG_ERROR("Cannot send heartbeat: not connected");
        return false;
    }
    
    try {
        // 验证socket状态
        if (!socket_ || !socket_->is_connected()) {
            LOG_ERROR("Cannot send heartbeat: socket not connected");
            is_connected_ = false;
            return false;
        }
        
        // 创建心跳消息
        protocol::Message heartbeat_msg(protocol::OperationType::HEARTBEAT);
        
        // 检查消息类型是否正确
        if (heartbeat_msg.get_operation_type() != protocol::OperationType::HEARTBEAT) {
            LOG_ERROR("Invalid heartbeat message type: %d", 
                     static_cast<int>(heartbeat_msg.get_operation_type()));
            return false;
        }
        
        // 编码消息
        std::vector<uint8_t> msg_buffer;
        if (!heartbeat_msg.encode(msg_buffer)) {
            LOG_ERROR("Failed to encode heartbeat message");
            return false;
        }
        
        // 验证编码后的消息头
        if (msg_buffer.size() < sizeof(protocol::ProtocolHeader)) {
            LOG_ERROR("Heartbeat message buffer too small: %zu bytes", msg_buffer.size());
            return false;
        }
        
        // 检查消息头
        protocol::ProtocolHeader* header = reinterpret_cast<protocol::ProtocolHeader*>(msg_buffer.data());

        // 复制packed结构体字段到本地变量
        uint32_t magic = header->magic;
        uint8_t type = header->type;
        uint32_t length = header->length;

        LOG_DEBUG("Encoded heartbeat message header - magic: 0x%08x, type: %d, length: %u", 
                 magic, type, length);
                 
        if (magic != protocol::PROTOCOL_MAGIC) {
            LOG_ERROR("Invalid magic in encoded heartbeat: 0x%08x, expected: 0x%08x", 
                     magic, protocol::PROTOCOL_MAGIC);
            
            // 尝试修复消息头
            header->magic = protocol::PROTOCOL_MAGIC;
            LOG_WARNING("Fixed magic value in heartbeat message");
        }
        
        if (type != static_cast<uint8_t>(protocol::OperationType::HEARTBEAT)) {
            LOG_ERROR("Invalid type in encoded heartbeat: %d, expected: %d", 
                     type, static_cast<uint8_t>(protocol::OperationType::HEARTBEAT));
            
            // 尝试修复消息头
            header->type = static_cast<uint8_t>(protocol::OperationType::HEARTBEAT);
            LOG_WARNING("Fixed type in heartbeat message");
        }
        
        // 发送消息，添加重试机制
        LOG_DEBUG("Sending heartbeat message, size: %zu bytes", msg_buffer.size());
        
        int send_retry = 0;
        const int max_send_retries = 3;  // 增加重试次数
        bool send_success = false;
        
        while (send_retry < max_send_retries && !send_success) {
            // 每次发送前检查连接状态
            if (!socket_ || !socket_->is_connected()) {
                LOG_ERROR("Connection lost before sending heartbeat");
                is_connected_ = false;
                return false;
            }
            
            network::SocketError err = socket_->send_all(msg_buffer.data(), msg_buffer.size());
            if (err == network::SocketError::SUCCESS) {
                send_success = true;
                LOG_DEBUG("Heartbeat message sent successfully");
            } else if (err == network::SocketError::TIMEOUT) {
                send_retry++;
                LOG_WARNING("Timeout while sending heartbeat, retry %d/%d", 
                           send_retry, max_send_retries);
                std::this_thread::sleep_for(std::chrono::milliseconds(200));  // 增加等待时间
            } else {
                LOG_ERROR("Failed to send heartbeat: %d", static_cast<int>(err));
                
                // 检查连接状态
                if (err == network::SocketError::CLOSED) {
                    LOG_ERROR("Connection closed while sending heartbeat");
                    is_connected_ = false;
                }
                
                return false;
            }
        }
        
        if (!send_success) {
            LOG_ERROR("Failed to send heartbeat after retries");
            return false;
        }
        
        // 短暂等待服务器处理 - 增加等待时间
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
        
        // 接收响应，添加重试机制
        protocol::ProtocolHeader header_buf;
        int recv_retry = 0;
        const int max_recv_retries = 8;  // 增加重试次数
        bool recv_success = false;
        
        while (recv_retry < max_recv_retries && !recv_success) {
            // 检查连接状态
            if (!socket_ || !socket_->is_connected()) {
                LOG_ERROR("Connection lost before receiving heartbeat response");
                is_connected_ = false;
                return false;
            }
            
            network::SocketError err = socket_->recv_all(&header_buf, sizeof(header_buf));
            if (err == network::SocketError::SUCCESS) {
                recv_success = true;
                LOG_DEBUG("Received heartbeat response header");
            } else if (err == network::SocketError::TIMEOUT) {
                recv_retry++;
                LOG_WARNING("Timeout while receiving heartbeat response, retry %d/%d", 
                           recv_retry, max_recv_retries);
                
                // 渐进式增加等待时间，避免太频繁重试
                std::this_thread::sleep_for(std::chrono::milliseconds(200 + recv_retry * 50));
                
                // 每2次重试发送一次新的心跳
                if (recv_retry % 2 == 0 && recv_retry > 0) {
                    LOG_INFO("Sending additional heartbeat during retry %d", recv_retry);
                    network::SocketError send_err = socket_->send_all(msg_buffer.data(), msg_buffer.size());
                    if (send_err != network::SocketError::SUCCESS) {
                        LOG_WARNING("Failed to send additional heartbeat: %d", 
                                  static_cast<int>(send_err));
                        // 不终止循环，继续等待之前的响应
                    }
                }
            } else {
                // 检查连接是否已关闭
                if (err == network::SocketError::CLOSED) {
                    LOG_WARNING("Connection closed by server while waiting for heartbeat response");
                    is_connected_ = false;
                } else {
                    LOG_WARNING("Failed to receive heartbeat response: %d", static_cast<int>(err));
                }
                
                // 心跳必须能发送和接收才算成功
                return false;
            }
        }
        
        if (!recv_success) {
            LOG_WARNING("Failed to receive heartbeat response after %d retries", max_recv_retries);
            // 心跳必须能发送和接收才算成功
            return false;
        }
        
        // 检查响应
        uint32_t magic_value = header_buf.magic;
        uint8_t type_value = header_buf.type;
        uint32_t length_value = header_buf.length;
        
        LOG_DEBUG("Received heartbeat response: magic=0x%08x, type=%d, length=%u", 
                 magic_value, type_value, length_value);
                 
        if (magic_value != protocol::PROTOCOL_MAGIC || 
            static_cast<protocol::OperationType>(type_value) != protocol::OperationType::HEARTBEAT) {
            LOG_WARNING("Invalid heartbeat response: magic=0x%08x, type=%d", magic_value, type_value);
            // 协议错误，但我们已经收到了响应，表明连接仍然存在
            // 这种情况下仍然认为心跳成功
            return true;
        }
        
        // 如果心跳消息有数据部分，需要读取并丢弃
        if (length_value > 0) {
            std::vector<uint8_t> payload(length_value);
            network::SocketError err = socket_->recv_all(payload.data(), payload.size());
            if (err != network::SocketError::SUCCESS) {
                LOG_WARNING("Failed to receive heartbeat payload: %d", static_cast<int>(err));
                // 忽略负载接收错误，因为心跳的主要目的是确认连接有效
                return true;
            }
        }
        
        LOG_DEBUG("Heartbeat successful");
        return true;
    } catch (const std::exception& e) {
        LOG_ERROR("Exception during heartbeat: %s", e.what());
        return false;
    }
}

void ClientCore::disconnect() {
    // 停止心跳线程
    stop_heartbeat_ = true;
    if (heartbeat_thread_.joinable()) {
        heartbeat_thread_.join();
    }
    
    if (socket_) {
        socket_->close();
        socket_.reset();
    }
    is_connected_ = false;
}

bool ClientCore::perform_key_exchange() {
    if (!is_connected_ || !socket_ || !socket_->is_connected()) {
        LOG_ERROR("Cannot perform key exchange: not connected");
        return false;
    }
    
    try {
        LOG_INFO("Starting key exchange process");
        
        // 生成DH参数和私钥
        utils::DHParams dh_params = utils::Encryption::generate_dh_params(dh_private_key_);
        if (dh_private_key_.empty() || dh_params.p.empty() || dh_params.g.empty() || dh_params.public_key.empty()) {
            LOG_ERROR("Failed to generate DH parameters");
            return false;
        }
        
        // 创建客户端Hello消息
        protocol::KeyExchangeMessage client_hello(protocol::KeyExchangePhase::CLIENT_HELLO);
        
        // 序列化DH参数
        std::vector<uint8_t> params_data;
        
        // 写入p的长度和数据
        uint32_t p_size = static_cast<uint32_t>(dh_params.p.size());
        params_data.resize(sizeof(uint32_t));
        std::memcpy(params_data.data(), &p_size, sizeof(uint32_t));
        params_data.insert(params_data.end(), dh_params.p.begin(), dh_params.p.end());
        
        // 写入g的长度和数据
        uint32_t g_size = static_cast<uint32_t>(dh_params.g.size());
        size_t g_offset = params_data.size();
        params_data.resize(g_offset + sizeof(uint32_t));
        std::memcpy(params_data.data() + g_offset, &g_size, sizeof(uint32_t));
        params_data.insert(params_data.end(), dh_params.g.begin(), dh_params.g.end());
        
        // 写入公钥的长度和数据
        uint32_t pub_size = static_cast<uint32_t>(dh_params.public_key.size());
        size_t pub_offset = params_data.size();
        params_data.resize(pub_offset + sizeof(uint32_t));
        std::memcpy(params_data.data() + pub_offset, &pub_size, sizeof(uint32_t));
        params_data.insert(params_data.end(), dh_params.public_key.begin(), dh_params.public_key.end());
        
        client_hello.set_exchange_params(params_data);
        
        // 编码消息
        std::vector<uint8_t> msg_buffer;
        if (!client_hello.encode(msg_buffer)) {
            LOG_ERROR("Failed to encode key exchange client hello message");
            return false;
        }
        
        // 发送消息
        network::SocketError err = socket_->send_all(msg_buffer.data(), msg_buffer.size());
        if (err != network::SocketError::SUCCESS) {
            LOG_ERROR("Failed to send key exchange client hello: %d", static_cast<int>(err));
            return false;
        }
        
        LOG_INFO("Sent key exchange CLIENT_HELLO, waiting for SERVER_HELLO");
        
        // 接收服务器响应
        protocol::ProtocolHeader header;
        err = socket_->recv_all(&header, sizeof(header));
        if (err != network::SocketError::SUCCESS) {
            LOG_ERROR("Failed to receive key exchange response header: %d", static_cast<int>(err));
            return false;
        }
        
        // 检查魔数和类型
        if (header.magic != protocol::PROTOCOL_MAGIC ||
            static_cast<protocol::OperationType>(header.type) != protocol::OperationType::KEY_EXCHANGE) {
            // 创建临时变量避免直接引用紧凑结构体中的字段
            uint32_t magic_val = header.magic;
            uint8_t type_val = header.type;
            LOG_ERROR("Invalid key exchange response header: magic=0x%08x, type=%d", 
                      magic_val, type_val);
            return false;
        }
        
        // 接收消息体
        std::vector<uint8_t> response_buffer(sizeof(protocol::ProtocolHeader) + header.length);
        std::memcpy(response_buffer.data(), &header, sizeof(protocol::ProtocolHeader));
        
        if (header.length > 0) {
            err = socket_->recv_all(response_buffer.data() + sizeof(protocol::ProtocolHeader), header.length);
            if (err != network::SocketError::SUCCESS) {
                LOG_ERROR("Failed to receive key exchange response body: %d", static_cast<int>(err));
                return false;
            }
        }
        
        // 解码响应
        protocol::Message response_msg;
        if (!response_msg.decode(response_buffer)) {
            LOG_ERROR("Failed to decode key exchange response");
            return false;
        }
        
        protocol::KeyExchangeMessage server_hello(response_msg);
        if (server_hello.get_exchange_phase() != protocol::KeyExchangePhase::SERVER_HELLO) {
            LOG_ERROR("Invalid key exchange phase in server response: %d", 
                      static_cast<int>(server_hello.get_exchange_phase()));
            return false;
        }
        
        // 解析服务器公钥
        const std::vector<uint8_t>& server_params = server_hello.get_exchange_params();
        if (server_params.empty()) {
            LOG_ERROR("Empty server key exchange params");
            return false;
        }
        
        // 解析服务器公钥
        if (server_params.size() < sizeof(uint32_t)) {
            LOG_ERROR("Invalid server key exchange params size");
            return false;
        }
        
        // 读取服务器公钥长度
        uint32_t server_key_size = 0;
        std::memcpy(&server_key_size, server_params.data(), sizeof(uint32_t));
        
        if (server_params.size() < sizeof(uint32_t) + server_key_size) {
            LOG_ERROR("Invalid server key exchange params: insufficient data");
            return false;
        }
        
        // 提取服务器公钥
        std::vector<uint8_t> server_public_key(server_params.begin() + sizeof(uint32_t),
                                              server_params.begin() + sizeof(uint32_t) + server_key_size);
        
        // 构建服务器DH参数
        utils::DHParams server_dh_params;
        server_dh_params.p = dh_params.p;      // 使用相同的p
        server_dh_params.g = dh_params.g;      // 使用相同的g
        server_dh_params.public_key = server_public_key; // 使用服务器的公钥
        
        // 计算共享密钥
        std::vector<uint8_t> shared_key = utils::Encryption::compute_dh_shared_key(
            server_dh_params, dh_private_key_);
        
        if (shared_key.empty()) {
            LOG_ERROR("Failed to compute shared key");
            return false;
        }
        
        // 派生AES密钥和IV
        utils::Encryption::derive_key_and_iv(shared_key, encryption_key_, encryption_iv_);
        
        if (encryption_key_.size() != 32 || encryption_iv_.size() != 16) {
            LOG_ERROR("Invalid derived key or IV size: key=%zu, iv=%zu", 
                      encryption_key_.size(), encryption_iv_.size());
            return false;
        }
        
        key_exchange_completed_ = true;
        LOG_INFO("Key exchange completed successfully");
        
        return true;
        
    } catch (const std::exception& e) {
        LOG_ERROR("Exception during key exchange: %s", e.what());
        return false;
    }
}

TransferResult ClientCore::upload(const TransferRequest& request) {
    TransferResult result;
    
    // 检查连接状态
    if (!is_connected_) {
        result.error_message = "Not connected to server";
        LOG_ERROR("%s", result.error_message.c_str());
        return result;
    }
    
    // 验证socket是否依然有效
    if (!socket_ || !socket_->is_connected()) {
        result.error_message = "Socket connection lost";
        LOG_ERROR("%s", result.error_message.c_str());
        is_connected_ = false;
        return result;
    }
    
    try {
        // 检查本地文件是否存在
        if (!fs::exists(request.local_file)) {
            result.error_message = "Local file does not exist: " + request.local_file;
            LOG_ERROR("%s", result.error_message.c_str());
            return result;
        }
        
        // 获取文件大小
        size_t file_size = fs::file_size(request.local_file);
        result.total_bytes = file_size;
        
        // 打开文件
        std::ifstream file(request.local_file, std::ios::binary);
        if (!file.is_open()) {
            result.error_message = "Failed to open local file: " + request.local_file;
            LOG_ERROR("%s", result.error_message.c_str());
            return result;
        }
        
        LOG_INFO("Uploading file %s to %s, size: %zu bytes", 
                 request.local_file.c_str(), request.remote_file.c_str(), file_size);
        
        // 记录开始时间
        auto start_time = std::chrono::high_resolution_clock::now();
        
        // 创建分块数量
        size_t chunks = (file_size + request.chunk_size - 1) / request.chunk_size;
        size_t chunk_index = 0;
        size_t remaining = file_size;
        size_t offset = 0;
        
        // 分块上传
        while (remaining > 0) {
            // 计算当前块大小
            size_t chunk_size = std::min(request.chunk_size, remaining);
            
            // 读取文件数据
            std::vector<uint8_t> buffer(chunk_size);
            file.read(reinterpret_cast<char*>(buffer.data()), chunk_size);
            if (!file) {
                result.error_message = "Failed to read local file";
                LOG_ERROR("%s", result.error_message.c_str());
                return result;
            }
            
            // 创建上传消息
            bool is_last_chunk = (chunk_index == chunks - 1);
            protocol::UploadMessage upload_msg(request.remote_file, offset, file_size, is_last_chunk);
            
            upload_msg.set_file_data(buffer.data(), chunk_size);
            
            // 编码消息
            std::vector<uint8_t> msg_buffer;
            
            // 如果启用了加密，设置加密标志并加密数据
            if (encryption_enabled_ && key_exchange_completed_) {
                // 设置加密标志
                upload_msg.set_encrypted(true);
                
                // 编码原始消息
                if (!upload_msg.encode(msg_buffer)) {
                    result.error_message = "Failed to encode upload message";
                    LOG_ERROR("%s", result.error_message.c_str());
                    return result;
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
                    result.error_message = "Failed to encode encrypted upload message";
                    LOG_ERROR("%s", result.error_message.c_str());
                    return result;
                }
                
                LOG_DEBUG("Upload message encrypted successfully");
            } else {
                // 不使用加密
                if (!upload_msg.encode(msg_buffer)) {
                    result.error_message = "Failed to encode upload message";
                    LOG_ERROR("%s", result.error_message.c_str());
                    return result;
                }
            }
            
            // 发送消息 - 添加重试机制
            LOG_INFO("Sending upload message, size: %zu bytes", msg_buffer.size());
            
            int send_retry_count = 0;
            const int max_send_retries = 3;
            bool send_success = false;
            
            while (send_retry_count < max_send_retries && !send_success) {
                network::SocketError err = socket_->send_all(msg_buffer.data(), msg_buffer.size());
                if (err == network::SocketError::SUCCESS) {
                    send_success = true;
                } else if (err == network::SocketError::TIMEOUT) {
                    send_retry_count++;
                    LOG_WARNING("Timeout while sending chunk, retry %d/%d", send_retry_count, max_send_retries);
                    std::this_thread::sleep_for(std::chrono::milliseconds(100));
                } else {
                    result.error_message = "Failed to send upload message";
                    LOG_ERROR("%s: %d", result.error_message.c_str(), static_cast<int>(err));
                    
                    // 检查连接状态
                    if (err == network::SocketError::CLOSED) {
                        is_connected_ = false;
                        result.error_message += " (Connection closed by server)";
                    }
                    
                    return result;
                }
            }
            
            if (!send_success) {
                result.error_message = "Failed to send upload message after retries";
                LOG_ERROR("%s", result.error_message.c_str());
                return result;
            }
            
            // 接收响应 - 改为接收整个协议消息
            // 首先接收协议头
            LOG_INFO("Waiting for server response...");
            protocol::ProtocolHeader header;
            
            // 设置一个较短的超时时间来尝试接收
            int retry_count = 0;
            const int max_retries = 5;  // 增加重试次数
            bool header_received = false;
            
            while (retry_count < max_retries && !header_received) {
                network::SocketError err = socket_->recv_all(&header, sizeof(header));
                if (err == network::SocketError::SUCCESS) {
                    header_received = true;
                } else if (err == network::SocketError::TIMEOUT) {
                    retry_count++;
                    LOG_WARNING("Timeout while receiving header, retry %d/%d", retry_count, max_retries);
                    std::this_thread::sleep_for(std::chrono::milliseconds(500));  // 增加延迟时间
                } else {
                    // 连接关闭或其他错误
                    if (err == network::SocketError::CLOSED) {
                        is_connected_ = false;
                        result.error_message = "Connection closed by server while receiving response header";
                    } else {
                        char err_buf[128] = {0};
                        strerror_r(errno, err_buf, sizeof(err_buf));
                        result.error_message = "Failed to receive response header";
                        LOG_ERROR("%s: %d, socket state: connected=%d, errno: %d (%s)", 
                                 result.error_message.c_str(), 
                                 static_cast<int>(err),
                                 socket_->is_connected(),
                                 errno, err_buf);
                    }
                    
                    return result;
                }
            }
            
            if (!header_received) {
                result.error_message = "Failed to receive response header after retries";
                LOG_ERROR("%s", result.error_message.c_str());
                
                // 检查连接状态
                if (!socket_->is_connected()) {
                    is_connected_ = false;
                    result.error_message += " (Connection lost)";
                }
                
                return result;
            }
            
            // 保存header字段到局部变量
            uint32_t magic_value = header.magic;
            uint8_t type_value = header.type;
            uint32_t length_value = header.length;
            
            LOG_INFO("Received response header - magic: 0x%08x, type: %d, length: %u", 
                     magic_value, type_value, length_value);
            
            // 检查魔数
            if (magic_value != protocol::PROTOCOL_MAGIC) {
                result.error_message = "Invalid protocol magic in response";
                LOG_ERROR("%s: expected 0x%08x, got 0x%08x", result.error_message.c_str(), 
                          protocol::PROTOCOL_MAGIC, magic_value);
                return result;
            }
            
            // 接收消息体
            std::vector<uint8_t> response_buffer(sizeof(protocol::ProtocolHeader) + length_value);
            std::memcpy(response_buffer.data(), &header, sizeof(protocol::ProtocolHeader));
            
            if (length_value > 0) {
                retry_count = 0;
                bool body_received = false;
                
                while (retry_count < max_retries && !body_received) {
                    network::SocketError err = socket_->recv_all(response_buffer.data() + sizeof(protocol::ProtocolHeader), length_value);
                    if (err == network::SocketError::SUCCESS) {
                        body_received = true;
                    } else if (err == network::SocketError::TIMEOUT) {
                        retry_count++;
                        LOG_WARNING("Timeout while receiving message body, retry %d/%d", retry_count, max_retries);
                        std::this_thread::sleep_for(std::chrono::milliseconds(500));  // 增加延迟时间
                    } else {
                        // 连接关闭或其他错误
                        if (err == network::SocketError::CLOSED) {
                            is_connected_ = false;
                            result.error_message = "Connection closed by server while receiving response body";
                        } else {
                            result.error_message = "Failed to receive response body";
                            LOG_ERROR("%s: %d", result.error_message.c_str(), static_cast<int>(err));
                        }
                        
                        return result;
                    }
                }
                
                if (!body_received) {
                    result.error_message = "Failed to receive response body after retries";
                    LOG_ERROR("%s", result.error_message.c_str());
                    
                    // 检查连接状态
                    if (!socket_->is_connected()) {
                        is_connected_ = false;
                        result.error_message += " (Connection lost)";
                    }
                    
                    return result;
                }
            }
            
            LOG_INFO("Received server response, size: %zu bytes", response_buffer.size());
            
            // 解析服务器响应
            protocol::Message response_msg;
            if (!response_msg.decode(response_buffer)) {
                result.error_message = "Failed to decode server response";
                LOG_ERROR("%s", result.error_message.c_str());
                return result;
            }
            
            // 检查响应是否加密
            bool is_encrypted = (response_msg.get_flags() & static_cast<uint8_t>(protocol::ProtocolFlags::ENCRYPTED)) != 0;
            LOG_DEBUG("Response message flags: 0x%02x, is_encrypted: %d", response_msg.get_flags(), is_encrypted ? 1 : 0);
            
            if (is_encrypted && encryption_enabled_ && key_exchange_completed_) {
                LOG_DEBUG("Response is encrypted, decrypting payload");
                
                // 获取负载并解密
                const std::vector<uint8_t>& encrypted_payload = response_msg.get_payload();
                std::vector<uint8_t> decrypted_payload = decrypt_data(encrypted_payload);
                
                // 创建一个新的消息来解析解密后的负载
                protocol::Message decrypted_msg(protocol::OperationType::UPLOAD);
                std::vector<uint8_t> decrypted_buffer(sizeof(protocol::ProtocolHeader) + decrypted_payload.size());
                
                // 复制原消息头但移除加密标志
                protocol::ProtocolHeader decrypted_header = header; // 使用之前读取的header
                decrypted_header.flags &= ~static_cast<uint8_t>(protocol::ProtocolFlags::ENCRYPTED);
                std::memcpy(decrypted_buffer.data(), &decrypted_header, sizeof(protocol::ProtocolHeader));
                
                // 添加解密后的负载
                std::memcpy(decrypted_buffer.data() + sizeof(protocol::ProtocolHeader), 
                           decrypted_payload.data(), decrypted_payload.size());
                
                // 解析解密后的消息
                if (!response_msg.decode(decrypted_buffer)) {
                    result.error_message = "Failed to decode decrypted server response";
                    LOG_ERROR("%s", result.error_message.c_str());
                    return result;
                }
                
                LOG_DEBUG("Response decrypted successfully");
            } else if (is_encrypted) {
                LOG_WARNING("Response is encrypted but encryption is not ready");
                result.error_message = "Received encrypted response but encryption is not enabled";
                return result;
            }
            
            // 检查响应类型
            if (response_msg.get_operation_type() == protocol::OperationType::ERROR) {
                std::string error_message(
                    reinterpret_cast<const char*>(response_msg.get_payload().data()),
                    response_msg.get_payload().size()
                );
                result.error_message = "Server error: " + error_message;
                LOG_ERROR("%s", result.error_message.c_str());
                return result;
            } else if (response_msg.get_operation_type() != protocol::OperationType::UPLOAD) {
                result.error_message = "Unexpected response type from server";
                LOG_ERROR("%s", result.error_message.c_str());
                return result;
            }
            
            // 检查是否是最后一个块的响应
            bool is_last_response = (response_msg.get_flags() & static_cast<uint8_t>(protocol::ProtocolFlags::LAST_CHUNK)) != 0;
            LOG_INFO("Server response: last chunk flag: %d", is_last_response);
            
            // 更新进度
            offset += chunk_size;
            remaining -= chunk_size;
            result.transferred_bytes = offset;
            chunk_index++;
            
            // 回调进度
            if (progress_callback_) {
                progress_callback_(result.transferred_bytes, result.total_bytes);
            }
            
            LOG_DEBUG("Uploaded chunk %zu/%zu, offset: %zu, chunk_size: %zu", 
                     chunk_index, chunks, offset, chunk_size);
                     
            // 给服务器一点时间处理
            if (remaining > 0) {
                std::this_thread::sleep_for(std::chrono::milliseconds(50));
            }
        }
        
        // 计算耗时
        auto end_time = std::chrono::high_resolution_clock::now();
        result.elapsed_seconds = std::chrono::duration<double>(end_time - start_time).count();
        
        // 设置结果
        result.success = true;
        
        LOG_INFO("Upload completed, transferred: %zu bytes, time: %.2f seconds, speed: %.2f MB/s", 
                 result.transferred_bytes, 
                 result.elapsed_seconds, 
                 (result.transferred_bytes / 1024.0 / 1024.0) / result.elapsed_seconds);
        
    } catch (const std::exception& e) {
        result.error_message = "Exception during upload: " + std::string(e.what());
        LOG_ERROR("%s", result.error_message.c_str());
    }
    
    return result;
}

std::future<TransferResult> ClientCore::upload_async(const TransferRequest& request) {
    return std::async(std::launch::async, &ClientCore::upload, this, request);
}

TransferResult ClientCore::download(const TransferRequest& request) {
    TransferResult result;
    
    // 检查连接状态
    if (!is_connected_) {
        result.error_message = "Not connected to server";
        LOG_ERROR("%s", result.error_message.c_str());
        return result;
    }
    
    try {
        // 确保目标目录存在
        fs::path local_path(request.local_file);
        if (!local_path.parent_path().empty()) {
            fs::create_directories(local_path.parent_path());
        }
        
        // 打开文件
        std::ofstream file(request.local_file, std::ios::binary);
        if (!file.is_open()) {
            result.error_message = "Failed to open local file for writing: " + request.local_file;
            LOG_ERROR("%s", result.error_message.c_str());
            return result;
        }
        
        LOG_INFO("Downloading file %s to %s", 
                 request.remote_file.c_str(), request.local_file.c_str());
        
        // 记录开始时间
        auto start_time = std::chrono::high_resolution_clock::now();
        
        // 创建下载请求消息
        protocol::DownloadMessage download_msg(request.remote_file, 0, 0);
        
        // 编码消息
        std::vector<uint8_t> msg_buffer;
        
        // 如果启用了加密，设置加密标志并加密数据
        if (encryption_enabled_ && key_exchange_completed_) {
            // 设置加密标志
            download_msg.set_encrypted(true);
            
            // 编码原始消息
            if (!download_msg.encode(msg_buffer)) {
                result.error_message = "Failed to encode download message";
                LOG_ERROR("%s", result.error_message.c_str());
                return result;
            }
            
            // 获取负载（跳过协议头）
            std::vector<uint8_t> payload(msg_buffer.begin() + sizeof(protocol::ProtocolHeader), 
                                       msg_buffer.end());
            
            // 加密负载
            std::vector<uint8_t> encrypted_payload = encrypt_data(payload);
            
            // 创建新的带加密标志的消息
            protocol::Message encrypted_msg(protocol::OperationType::DOWNLOAD);
            encrypted_msg.set_flags(static_cast<uint8_t>(protocol::ProtocolFlags::ENCRYPTED));
            encrypted_msg.set_payload(encrypted_payload.data(), encrypted_payload.size());
            
            // 编码加密消息
            msg_buffer.clear();
            if (!encrypted_msg.encode(msg_buffer)) {
                result.error_message = "Failed to encode encrypted download message";
                LOG_ERROR("%s", result.error_message.c_str());
                return result;
            }
            
            LOG_DEBUG("Download message encrypted successfully");
        } else {
            // 不使用加密
            if (!download_msg.encode(msg_buffer)) {
                result.error_message = "Failed to encode download message";
                LOG_ERROR("%s", result.error_message.c_str());
                return result;
            }
        }
        
        // 发送消息
        network::SocketError err = socket_->send_all(msg_buffer.data(), msg_buffer.size());
        if (err != network::SocketError::SUCCESS) {
            result.error_message = "Failed to send download message";
            LOG_ERROR("%s", result.error_message.c_str());
            return result;
        }
        
        // 接收文件数据
        size_t offset = 0;
        bool last_chunk = false;
        
        LOG_DEBUG("Starting download loop for file %s", request.remote_file.c_str());
        
        while (!last_chunk) {
            // 接收消息头部
            protocol::ProtocolHeader header;
            err = socket_->recv_all(&header, sizeof(header));
            if (err != network::SocketError::SUCCESS) {
                result.error_message = "Failed to receive header";
                LOG_ERROR("%s: %d", result.error_message.c_str(), static_cast<int>(err));
                return result;
            }
            
            // 保存header字段到局部变量
            uint32_t magic_value = header.magic;
            uint8_t type_value = header.type;
            uint32_t length_value = header.length;
            
            LOG_DEBUG("Received header: magic=0x%08x, type=%d, length=%u", 
                     magic_value, type_value, length_value);
            
            // 检查魔数
            if (magic_value != protocol::PROTOCOL_MAGIC) {
                result.error_message = "Invalid protocol magic";
                LOG_ERROR("%s: expected 0x%08x, got 0x%08x", result.error_message.c_str(), 
                          protocol::PROTOCOL_MAGIC, magic_value);
                return result;
            }
            
            // 检查操作类型
            if (static_cast<protocol::OperationType>(type_value) != protocol::OperationType::DOWNLOAD) {
                result.error_message = "Invalid operation type";
                LOG_ERROR("%s: expected %d, got %d", result.error_message.c_str(), 
                          static_cast<int>(protocol::OperationType::DOWNLOAD), type_value);
                return result;
            }
            
            // 接收消息体
            std::vector<uint8_t> payload;
            if (length_value > 0) {
                payload.resize(length_value);
                LOG_DEBUG("Receiving payload of size %u", length_value);
                err = socket_->recv_all(payload.data(), payload.size());
                if (err != network::SocketError::SUCCESS) {
                    result.error_message = "Failed to receive payload";
                    LOG_ERROR("%s: %d", result.error_message.c_str(), static_cast<int>(err));
                    return result;
                }
            }
            
            // 解析消息
            protocol::Message msg;
            std::vector<uint8_t> complete_message(sizeof(protocol::ProtocolHeader) + length_value);
            std::memcpy(complete_message.data(), &header, sizeof(protocol::ProtocolHeader));
            if (length_value > 0) {
                std::memcpy(complete_message.data() + sizeof(protocol::ProtocolHeader), payload.data(), payload.size());
            }

            LOG_DEBUG("Complete message size: %zu", complete_message.size());
            if (!msg.decode(complete_message)) {
                result.error_message = "Failed to decode download response message";
                LOG_ERROR("%s", result.error_message.c_str());
                return result;
            }

            // 检查响应是否加密
            bool is_encrypted = (msg.get_flags() & static_cast<uint8_t>(protocol::ProtocolFlags::ENCRYPTED)) != 0;
            LOG_DEBUG("Response message flags: 0x%02x, is_encrypted: %d", msg.get_flags(), is_encrypted ? 1 : 0);
            
            if (is_encrypted && encryption_enabled_ && key_exchange_completed_) {
                LOG_DEBUG("Response is encrypted, decrypting payload");
                
                // 获取负载并解密
                const std::vector<uint8_t>& encrypted_payload = msg.get_payload();
                LOG_DEBUG("Encrypted payload size: %zu", encrypted_payload.size());
                
                std::vector<uint8_t> decrypted_payload = decrypt_data(encrypted_payload);
                
                // 提取文件数据
                size_t metadata_size = sizeof(uint64_t) * 2;
                size_t file_data_size = decrypted_payload.size() - metadata_size;

                // 解析元数据
                uint64_t offset_be = 0;
                uint64_t total_size_be = 0;
                if (decrypted_payload.size() >= metadata_size) {
                    std::memcpy(&offset_be, decrypted_payload.data(), sizeof(uint64_t));
                    std::memcpy(&total_size_be, decrypted_payload.data() + sizeof(uint64_t), sizeof(uint64_t));
                
                    // 转换为主机字节序
                    uint64_t offset = protocol::net_to_host64(offset_be);
                    uint64_t total_size = protocol::net_to_host64(total_size_be);
                
                    LOG_DEBUG("Metadata parsed: offset=%llu, total_size=%llu", offset, total_size);
                }
                
                // 检查文件数据大小是否合理
                if (file_data_size > 1024 * 1024 * 1024) {  // 超过1GB，很可能是错误的
                    LOG_ERROR("Unreasonable file_data_size: %zu", file_data_size);
                    return result;
                }
                
                std::vector<uint8_t> file_data;
                
                if (file_data_size > 0) {
                    file_data.resize(file_data_size);
                    // 从元数据后面提取文件数据，跳过偏移量和总大小字段
                    std::memcpy(file_data.data(), decrypted_payload.data() + metadata_size, file_data_size);
                }
                
                // 创建新的下载消息
                protocol::DownloadMessage download_response;
                // 设置响应数据，不包含元数据
                download_response.set_response_data(file_data.data(), file_data.size(), file_data.size(), true);  // 设置LAST_CHUNK标志
                
                // 更新原始消息
                msg = download_response;
                
                LOG_DEBUG("Successfully parsed decrypted download message: total_size=%zu, data_size=%zu", 
                          file_data_size, file_data.size());
            } else if (is_encrypted) {
                LOG_WARNING("Response is encrypted but encryption is not ready");
                result.error_message = "Received encrypted response but encryption is not enabled";
                return result;
            }

            protocol::DownloadMessage response(msg);
            
            // 获取响应数据
            const auto& response_data = response.get_response_data();
            LOG_DEBUG("Response data size: %zu, total_size: %llu", 
                     response_data.size(), response.get_total_size());
            
            // 写入文件
            if (!response_data.empty()) {
                LOG_DEBUG("Writing %zu bytes to file at offset %zu", response_data.size(), offset);
                file.write(reinterpret_cast<const char*>(response_data.data()), 
                           response_data.size());
                
                // 检查写入是否成功
                if (!file) {
                    result.error_message = "Failed to write to local file";
                    LOG_ERROR("%s", result.error_message.c_str());
                    return result;
                }
                
                // 确保数据写入磁盘
                file.flush();
                
                // 更新进度
                offset += response_data.size();
                result.transferred_bytes = offset;
                
                // 回调进度
                if (progress_callback_) {
                    progress_callback_(result.transferred_bytes, response.get_total_size());
                }
            } else {
                LOG_WARNING("Received empty response data chunk");
            }
            
            // 检查是否为最后一个块
            last_chunk = response.is_last_chunk();
            if (last_chunk) {
                result.total_bytes = response.get_total_size();
                LOG_DEBUG("Last chunk received, total size: %zu", result.total_bytes);
            }
            
            LOG_DEBUG("Downloaded chunk, offset: %zu, chunk_size: %zu, total_size: %zu, last_chunk: %d", 
                     offset, response_data.size(), result.total_bytes, last_chunk ? 1 : 0);
        }
        
        // 关闭文件
        file.close();
        
        // 验证文件大小
        if (fs::exists(request.local_file)) {
            size_t actual_size = fs::file_size(request.local_file);
            if (actual_size != result.total_bytes) {
                result.error_message = "File size mismatch: expected " + 
                                     std::to_string(result.total_bytes) + 
                                     " bytes, got " + std::to_string(actual_size) + " bytes";
                LOG_ERROR("%s", result.error_message.c_str());
                return result;
            }
        }
        
        // 计算耗时
        auto end_time = std::chrono::high_resolution_clock::now();
        result.elapsed_seconds = std::chrono::duration<double>(end_time - start_time).count();
        
        // 设置结果
        result.success = true;
        
        LOG_INFO("Download completed, transferred: %zu bytes, time: %.2f seconds, speed: %.2f MB/s", 
                 result.transferred_bytes, 
                 result.elapsed_seconds, 
                 (result.transferred_bytes / 1024.0 / 1024.0) / result.elapsed_seconds);
        
    } catch (const std::exception& e) {
        result.error_message = "Exception during download: " + std::string(e.what());
        LOG_ERROR("%s", result.error_message.c_str());
    }
    
    return result;
}

std::future<TransferResult> ClientCore::download_async(const TransferRequest& request) {
    return std::async(std::launch::async, &ClientCore::download, this, request);
}

// 函数已在头文件中内联定义
// void ClientCore::set_progress_callback(ProgressCallback callback) {
//     progress_callback_ = std::move(callback);
// }

bool ClientCore::is_connected() const {
    return is_connected_ && socket_ && socket_->is_connected();
}

std::vector<uint8_t> ClientCore::encrypt_data(const std::vector<uint8_t>& data) {
    if (!encryption_enabled_ || !key_exchange_completed_ || data.empty()) {
        return data;
    }
    
    return utils::Encryption::aes_encrypt(data, encryption_key_, encryption_iv_);
}

std::vector<uint8_t> ClientCore::decrypt_data(const std::vector<uint8_t>& data) {
    if (!encryption_enabled_ || !key_exchange_completed_ || data.empty()) {
        return data;
    }
    
    return utils::Encryption::aes_decrypt(data, encryption_key_, encryption_iv_);
}

} // namespace client
} // namespace ft 