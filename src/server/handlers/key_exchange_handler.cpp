#include "key_exchange_handler.h"
#include "../core/client_session.h"
#include "../../common/protocol/messages/key_exchange_message.h"
#include "../../common/protocol/protocol.h"
#include "../../common/utils/crypto/encryption.h"
#include <cstring>
#include <openssl/evp.h>
#include <openssl/param_build.h>
#include <openssl/core_names.h>
#include <openssl/bn.h>

namespace ft {
namespace server {

KeyExchangeHandler::KeyExchangeHandler(ClientSession& session)
    : ProtocolHandler(session) {
}

bool KeyExchangeHandler::handle(const std::vector<uint8_t>& buffer) {
    try {
        LOG_INFO("Session %zu: Received key exchange message, buffer size: %zu", get_session_id(), buffer.size());
        
        // 解析密钥交换消息
        protocol::Message msg;
        if (!msg.decode(buffer)) {
            LOG_ERROR("Session %zu: Failed to decode key exchange message", get_session_id());
            return false;
        }
        
        protocol::KeyExchangeMessage key_msg(msg);
        protocol::KeyExchangePhase phase = key_msg.get_exchange_phase();
        
        LOG_INFO("Session %zu: Key exchange phase: %d", get_session_id(), static_cast<int>(phase));
        
        if (phase == protocol::KeyExchangePhase::CLIENT_HELLO) {
            return process_client_hello(key_msg);
        } else {
            LOG_ERROR("Session %zu: Unexpected key exchange phase: %d", 
                      get_session_id(), static_cast<int>(phase));
            return false;
        }
        
    } catch (const std::exception& e) {
        LOG_ERROR("Session %zu: Exception while handling key exchange: %s", get_session_id(), e.what());
        return false;
    }
}

bool KeyExchangeHandler::process_client_hello(const protocol::KeyExchangeMessage& key_msg) {
    // 获取客户端参数
    std::vector<uint8_t> client_params = key_msg.get_exchange_params();
    if (client_params.empty()) {
        LOG_ERROR("Session %zu: Empty client key exchange params", get_session_id());
        return false;
    }
    
    // 从客户端参数中提取DH参数
    if (client_params.size() < sizeof(uint32_t)) {
        LOG_ERROR("Session %zu: Invalid client params format", get_session_id());
        return false;
    }
    
    // 读取p的长度和数据
    uint32_t p_size = 0;
    std::memcpy(&p_size, client_params.data(), sizeof(uint32_t));
    
    if (client_params.size() < sizeof(uint32_t) + p_size) {
        LOG_ERROR("Session %zu: Client params too short for p", get_session_id());
        return false;
    }
    
    std::vector<uint8_t> p(client_params.begin() + sizeof(uint32_t), 
                           client_params.begin() + sizeof(uint32_t) + p_size);
    
    // 读取g的长度和数据
    size_t g_offset = sizeof(uint32_t) + p_size;
    if (client_params.size() < g_offset + sizeof(uint32_t)) {
        LOG_ERROR("Session %zu: Client params too short for g length", get_session_id());
        return false;
    }
    
    uint32_t g_size = 0;
    std::memcpy(&g_size, client_params.data() + g_offset, sizeof(uint32_t));
    
    if (client_params.size() < g_offset + sizeof(uint32_t) + g_size) {
        LOG_ERROR("Session %zu: Client params too short for g", get_session_id());
        return false;
    }
    
    std::vector<uint8_t> g(client_params.begin() + g_offset + sizeof(uint32_t),
                          client_params.begin() + g_offset + sizeof(uint32_t) + g_size);
    
    // 读取客户端公钥
    size_t pub_offset = g_offset + sizeof(uint32_t) + g_size;
    if (client_params.size() < pub_offset + sizeof(uint32_t)) {
        LOG_ERROR("Session %zu: Client params too short for public key length", get_session_id());
        return false;
    }
    
    uint32_t pub_size = 0;
    std::memcpy(&pub_size, client_params.data() + pub_offset, sizeof(uint32_t));
    
    if (client_params.size() < pub_offset + sizeof(uint32_t) + pub_size) {
        LOG_ERROR("Session %zu: Client params too short for public key", get_session_id());
        return false;
    }
    
    std::vector<uint8_t> client_public_key(
        client_params.begin() + pub_offset + sizeof(uint32_t),
        client_params.begin() + pub_offset + sizeof(uint32_t) + pub_size);
    
    LOG_INFO("Session %zu: Extracted DH params - p: %zu bytes, g: %zu bytes, client public key: %zu bytes", 
             get_session_id(), p.size(), g.size(), client_public_key.size());
    
    // 使用与客户端相同的方法生成服务器DH密钥对
    // 直接使用命名组生成，确保兼容性
    std::vector<uint8_t> server_private_key;
    utils::DHParams server_dh_params = utils::Encryption::generate_dh_params(server_private_key);
    
    if (server_private_key.empty() || server_dh_params.public_key.empty()) {
        LOG_ERROR("Session %zu: Failed to generate server DH key pair", get_session_id());
        return false;
    }
    
    LOG_INFO("Session %zu: Generated server DH key pair successfully", get_session_id());
    
    // 构建客户端DH参数结构（使用客户端发送的参数）
    utils::DHParams client_dh_params;
    client_dh_params.p = p;
    client_dh_params.g = g;
    client_dh_params.public_key = client_public_key;
    
    // 计算共享密钥
    std::vector<uint8_t> shared_key = utils::Encryption::compute_dh_shared_key(
        client_dh_params, server_private_key);
    
    if (shared_key.empty()) {
        LOG_ERROR("Session %zu: Failed to compute shared key", get_session_id());
        return false;
    }
    
    LOG_INFO("Session %zu: Computed shared key successfully", get_session_id());
    
    // 派生AES密钥和IV
    std::vector<uint8_t> encryption_key, encryption_iv;
    utils::Encryption::derive_key_and_iv(shared_key, encryption_key, encryption_iv);
    
    if (encryption_key.size() != 32 || encryption_iv.size() != 16) {
        LOG_ERROR("Session %zu: Invalid derived key or IV size: key=%zu, iv=%zu", 
                  get_session_id(), encryption_key.size(), encryption_iv.size());
        return false;
    }
    
    // 发送服务器Hello响应（发送服务器的公钥）
    if (!send_server_hello(server_dh_params.public_key)) {
        return false;
    }
    
    // 设置加密参数到会话
    set_encryption_keys(encryption_key, encryption_iv, server_private_key);
    
    LOG_INFO("Session %zu: Key exchange completed successfully", get_session_id());
    return true;
}

bool KeyExchangeHandler::send_server_hello(const std::vector<uint8_t>& server_public_key) {
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
        LOG_ERROR("Session %zu: Failed to encode server hello message", get_session_id());
        return false;
    }
    
    // 发送响应
    network::SocketError err = get_socket().send_all(response_buffer.data(), response_buffer.size());
    if (err != network::SocketError::SUCCESS) {
        LOG_ERROR("Session %zu: Failed to send server hello: %d", get_session_id(), static_cast<int>(err));
        return false;
    }
    
    LOG_DEBUG("Session %zu: Server hello sent successfully", get_session_id());
    return true;
}

void KeyExchangeHandler::set_encryption_keys(const std::vector<uint8_t>& encryption_key,
                                            const std::vector<uint8_t>& encryption_iv,
                                            const std::vector<uint8_t>& dh_private_key) {
    // 通过ClientSession设置加密参数
    session_.set_encryption_params(encryption_key, encryption_iv, dh_private_key);
    session_.enable_encryption();
}

} // namespace server
} // namespace ft 