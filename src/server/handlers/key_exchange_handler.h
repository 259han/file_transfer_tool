#pragma once

#include "protocol_handler.h"

namespace ft {
namespace protocol {
    class KeyExchangeMessage; // 前向声明
}

namespace server {

/**
 * @brief 密钥交换处理器
 * 负责处理DH密钥交换协议
 */
class KeyExchangeHandler : public ProtocolHandler {
public:
    /**
     * @brief 构造函数
     * @param session 客户端会话引用
     */
    explicit KeyExchangeHandler(ClientSession& session);
    
    /**
     * @brief 析构函数
     */
    ~KeyExchangeHandler() override = default;
    
    /**
     * @brief 处理密钥交换消息
     * @param buffer 消息缓冲区
     * @return 是否处理成功
     */
    bool handle(const std::vector<uint8_t>& buffer) override;

private:
    /**
     * @brief 处理客户端Hello消息
     * @param key_msg 密钥交换消息
     * @return 是否处理成功
     */
    bool process_client_hello(const protocol::KeyExchangeMessage& key_msg);
    
    /**
     * @brief 发送服务器Hello响应
     * @param server_public_key 服务器公钥
     * @return 是否发送成功
     */
    bool send_server_hello(const std::vector<uint8_t>& server_public_key);
    
    /**
     * @brief 设置加密密钥
     * @param encryption_key 加密密钥
     * @param encryption_iv 加密IV
     * @param dh_private_key DH私钥
     */
    void set_encryption_keys(const std::vector<uint8_t>& encryption_key,
                            const std::vector<uint8_t>& encryption_iv,
                            const std::vector<uint8_t>& dh_private_key);
};

} // namespace server
} // namespace ft 