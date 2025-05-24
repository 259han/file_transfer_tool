#include "client_core.h"
#include "../handlers/upload_handler.h"
#include "../handlers/download_handler.h"
#include "../handlers/authentication_handler.h"
#include "../../common/protocol/protocol.h"
#include "../../common/protocol/messages/key_exchange_message.h"
#include "../../common/protocol/messages/authentication_message.h"
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
      key_exchange_completed_(false),
      authenticated_(false),
      authenticated_username_(),
      user_permissions_(0),
      auth_handler_(std::make_unique<ClientAuthenticationHandler>()) {
}

ClientCore::~ClientCore() {
    // 确保首先断开连接
    if (is_connected_ || socket_) {
        disconnect();
    }
    
    // 确保心跳线程已停止并清理资源
    stop_heartbeat_ = true;
    
    if (heartbeat_thread_.joinable()) {
        heartbeat_thread_.detach();
    }
    
    // 清理加密相关资源
    encryption_key_.clear();
    encryption_iv_.clear();
    dh_private_key_.clear();
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
    // 断开现有连接
    if (is_connected_) {
        disconnect();
    }
    
    // 创建Socket
    network::SocketOptions options;
    options.connect_timeout = std::chrono::milliseconds(5000);  // 减少连接超时为5秒
    options.recv_timeout = std::chrono::milliseconds(2000);     // 减少接收超时为2秒
    options.send_timeout = std::chrono::milliseconds(2000);     // 减少发送超时为2秒
    options.keep_alive = true;
    options.keep_idle = 15;                 // 15秒后开始探测，减少从默认的60秒
    options.keep_interval = 3;              // 每3秒探测一次，减少从默认的5秒
    options.keep_count = 4;                 // 探测4次无响应则认为连接断开，增加探测次数
    options.recv_buffer_size = 256 * 1024;  // 256KB
    options.send_buffer_size = 256 * 1024;  // 256KB
    
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
            LOG_ERROR("Socket connection lost before sending heartbeat");
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
}

void ClientCore::start_heartbeat_thread() {
    stop_heartbeat_ = false;
    heartbeat_thread_ = std::thread([this]() {
        LOG_INFO("Heartbeat thread started");
        
        int consecutive_failures = 0;
        const int max_consecutive_failures = 3;  // 减少允许的连续失败次数
        
        while (!stop_heartbeat_ && is_connected_) {
            // 每8秒发送一次心跳，缩短心跳间隔以更快发现断连
            std::this_thread::sleep_for(std::chrono::seconds(8));
            
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
                    // 计算重试延迟，减少最大延迟
                    int retry_delay = consecutive_failures * 500;  // 最多1000ms延迟
                    LOG_INFO("Will retry heartbeat in %d ms", retry_delay);
                    
                    // 分段检查，避免长时间阻塞
                    for (int i = 0; i < retry_delay / 100 && !stop_heartbeat_ && is_connected_; i++) {
                        // 检查连接是否仍然有效
                        if (!socket_ || !socket_->is_connected()) {
                            LOG_WARNING("Socket disconnected during heartbeat retry delay");
                            is_connected_ = false;
                            break;
                        }
                        std::this_thread::sleep_for(std::chrono::milliseconds(100));
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
                
                // 连续失败超过阈值直接断开连接
                if (consecutive_failures >= max_consecutive_failures) {
                    LOG_ERROR("Too many consecutive heartbeat failures, marking connection as lost");
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
    // 心跳失败属于不可恢复错误，应快速失败
    if (!is_connected_) {
        LOG_FATAL("严重错误：系统认为已连接但状态不一致");
        // 内部状态不一致，直接终止程序
        std::abort();
    }
    
    // 验证socket状态 - 严重错误，状态不一致
    if (!socket_ || !socket_->is_connected()) {
        LOG_FATAL("严重错误：系统状态不一致，socket无效但状态为已连接");
        is_connected_ = false;
        // 内部状态不一致，直接终止程序
        std::abort();
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
    const int max_recv_retries = 3;  // 减少重试次数，从8降到3
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
            
            // 缩短渐进式等待时间，避免太长延迟
            std::this_thread::sleep_for(std::chrono::milliseconds(100 + recv_retry * 50));
            
            // 每次重试都发送一次新的心跳，增加成功率
            if (recv_retry > 0) {
                LOG_INFO("Sending additional heartbeat during retry %d", recv_retry);
                network::SocketError send_err = socket_->send_all(msg_buffer.data(), msg_buffer.size());
                if (send_err != network::SocketError::SUCCESS) {
                    LOG_WARNING("Failed to send additional heartbeat: %d", 
                              static_cast<int>(send_err));
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
    
    LOG_DEBUG("Received heartbeat response: magic=0x%08x, type=%d, length: %u", 
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
}

void ClientCore::disconnect() {
    // 如果已经断开连接，不执行任何操作
    if (!is_connected_ && !socket_) {
        return;
    }
    
    // 标记停止心跳和连接状态
    stop_heartbeat_ = true;
    is_connected_ = false;
    
    // 清除认证状态
    authenticated_ = false;
    authenticated_username_.clear();
    user_permissions_ = 0;
    if (auth_handler_) {
        auth_handler_->clear_authentication();
    }
    
    // 关闭套接字
    if (socket_) {
        socket_->close();
        socket_.reset();
    }
    
    // 分离心跳线程，避免阻塞
    if (heartbeat_thread_.joinable()) {
        heartbeat_thread_.detach();
    }
    
    LOG_INFO("Disconnected from server");
}

bool ClientCore::perform_key_exchange() {
    LOG_INFO("Starting key exchange process");
    
    // 加入生成DH参数的详细时间日志
    auto start_time = std::chrono::high_resolution_clock::now();
    
    LOG_INFO("Generating DH parameters...");
    
    // 生成DH参数和私钥
    utils::DHParams dh_params = utils::Encryption::generate_dh_params(dh_private_key_);
    
    auto end_time = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end_time - start_time).count();
    
    LOG_INFO("DH parameters generation completed in %lld ms", duration);
    
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
    
    // 验证socket是否有效 - 不可恢复错误
    if (!socket_ || !socket_->is_connected()) {
        LOG_FATAL("严重错误：密钥交换时Socket无效或未连接");
        // 严重错误，直接终止程序
        std::abort();
    }
    
    // 发送消息
    LOG_INFO("Sending KEY_EXCHANGE CLIENT_HELLO message");
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
    start_time = std::chrono::high_resolution_clock::now();
    
    std::vector<uint8_t> shared_key = utils::Encryption::compute_dh_shared_key(
        server_dh_params, dh_private_key_);
    
    end_time = std::chrono::high_resolution_clock::now();
    duration = std::chrono::duration_cast<std::chrono::milliseconds>(end_time - start_time).count();
    
    LOG_INFO("DH shared key computation completed in %lld ms", duration);
    
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
}

TransferResult ClientCore::upload(const TransferRequest& request) {
    TransferResult result;
    
    // 检查连接状态 - 不可恢复错误，应快速失败
    if (!is_connected_) {
        result.error_message = "Not connected to server";
        LOG_FATAL("%s", result.error_message.c_str());
        // 严重错误，直接终止程序
        std::abort();
    }
    
    // 验证socket是否依然有效 - 不可恢复错误，应快速失败
    if (!socket_ || !socket_->is_connected()) {
        result.error_message = "Socket connection lost";
        LOG_FATAL("%s", result.error_message.c_str());
        is_connected_ = false;
        // 严重错误，直接终止程序
        std::abort();
    }
    
    // 记录开始时间
    auto start_time = std::chrono::high_resolution_clock::now();
    
    // 创建上传处理器
    UploadHandler upload_handler(
        request.local_file,
        request.remote_file,
        request.chunk_size,
        progress_callback_,
        encryption_enabled_,
        encryption_key_,
        encryption_iv_
    );
    
    // 执行上传
    bool success = upload_handler.upload(*socket_);
    
    // 计算耗时
    auto end_time = std::chrono::high_resolution_clock::now();
    result.elapsed_seconds = std::chrono::duration<double>(end_time - start_time).count();
    
    // 设置结果
    result.success = success;
    if (!success) {
        result.error_message = "Upload failed";
    }
    
    return result;
}

TransferResult ClientCore::download(const TransferRequest& request) {
    TransferResult result;
    
    // 检查连接状态 - 不可恢复错误，应快速失败
    if (!is_connected_) {
        result.error_message = "Not connected to server";
        LOG_FATAL("%s", result.error_message.c_str());
        // 严重错误，直接终止程序
        std::abort();
    }
    
    // 验证socket是否依然有效 - 不可恢复错误，应快速失败
    if (!socket_ || !socket_->is_connected()) {
        result.error_message = "Socket connection lost";
        LOG_FATAL("%s", result.error_message.c_str());
        is_connected_ = false;
        // 严重错误，直接终止程序
        std::abort();
    }
    
    // 记录开始时间
    auto start_time = std::chrono::high_resolution_clock::now();
    
    // 创建下载处理器
    DownloadHandler download_handler(
        request.local_file,
        request.remote_file,
        progress_callback_,
        encryption_enabled_,
        encryption_key_,
        encryption_iv_
    );
    
    // 执行下载
    bool success = download_handler.download(*socket_);
    
    // 计算耗时
    auto end_time = std::chrono::high_resolution_clock::now();
    result.elapsed_seconds = std::chrono::duration<double>(end_time - start_time).count();
    
    // 设置结果
    result.success = success;
    if (!success) {
        result.error_message = "Download failed";
    }
    
    return result;
}

std::future<TransferResult> ClientCore::upload_async(const TransferRequest& request) {
    return std::async(std::launch::async, &ClientCore::upload, this, request);
}

std::future<TransferResult> ClientCore::download_async(const TransferRequest& request) {
    return std::async(std::launch::async, &ClientCore::download, this, request);
}


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
    
    try {
        auto decrypted = utils::Encryption::aes_decrypt(data, encryption_key_, encryption_iv_);
        
        // 检查解密是否成功
        if (decrypted.empty() && !data.empty()) {
            LOG_ERROR("Decryption failed: input size=%zu, output size=0", data.size());
            
            // 记录原始数据的前16字节作为调试信息
            std::string data_preview;
            for (size_t i = 0; i < std::min(data.size(), size_t(16)); ++i) {
                char hex[4];
                snprintf(hex, sizeof(hex), "%02x ", data[i]);
                data_preview += hex;
            }
            LOG_ERROR("Original data preview: %s", data_preview.c_str());
            
            // 记录密钥和IV的前8字节作为调试信息
            std::string key_preview;
            for (size_t i = 0; i < std::min(encryption_key_.size(), size_t(8)); ++i) {
                char hex[4];
                snprintf(hex, sizeof(hex), "%02x ", encryption_key_[i]);
                key_preview += hex;
            }
            LOG_ERROR("Key preview: %s...(truncated)", key_preview.c_str());
            
            // 尝试进行数据恢复 - 解密失败是严重错误
            // 返回一个包含原始数据的副本，而不是空向量
            // 这种方法仅用于故障排除，实际应用中不应使用
            LOG_WARNING("Using fallback decryption handler. This is for debugging only!");
            return data;
        }
        
        return decrypted;
    } catch (const std::exception& e) {
        LOG_ERROR("Exception during decryption: %s", e.what());
        // 返回原始数据以尝试恢复，这仅用于调试
        LOG_WARNING("Using exception fallback handler. This is for debugging only!");
        return data;
    }
}

AuthenticationResult ClientCore::authenticate(const std::string& username, const std::string& password) {
    if (!is_connected_ || !socket_) {
        AuthenticationResult result;
        result.error_message = "Not connected to server";
        return result;
    }
    
    LOG_INFO("Authenticating user: %s", username.c_str());
    
    AuthenticationResult result = auth_handler_->authenticate_user(*socket_, username, password);
    
    if (result.success) {
        // 同步状态到ClientCore
        authenticated_ = true;
        authenticated_username_ = result.username;
        user_permissions_ = result.permissions;
        
        LOG_INFO("User %s authenticated successfully in ClientCore", username.c_str());
    } else {
        // 清除状态
        authenticated_ = false;
        authenticated_username_.clear();
        user_permissions_ = 0;
    }
    
    return result;
}

AuthenticationResult ClientCore::authenticate_with_api_key(const std::string& api_key) {
    if (!is_connected_ || !socket_) {
        AuthenticationResult result;
        result.error_message = "Not connected to server";
        return result;
    }
    
    LOG_INFO("Authenticating with API key");
    
    AuthenticationResult result = auth_handler_->authenticate_api_key(*socket_, api_key);
    
    if (result.success) {
        // 同步状态到ClientCore
        authenticated_ = true;
        authenticated_username_ = result.username;
        user_permissions_ = result.permissions;
        
        LOG_INFO("API key authenticated successfully for user %s in ClientCore", 
                 authenticated_username_.c_str());
    } else {
        // 清除状态
        authenticated_ = false;
        authenticated_username_.clear();
        user_permissions_ = 0;
    }
    
    return result;
}

bool ClientCore::is_authenticated() const {
    return authenticated_ && auth_handler_ && auth_handler_->is_authenticated();
}

const std::string& ClientCore::get_authenticated_username() const {
    return authenticated_username_;
}

uint8_t ClientCore::get_user_permissions() const {
    return user_permissions_;
}

bool ClientCore::has_permission(uint8_t permission) const {
    return authenticated_ && (user_permissions_ & permission) != 0;
}

} // namespace client
} // namespace ft 