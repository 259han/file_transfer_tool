#pragma once

#include <vector>
#include <cstdint>
#include "../../common/network/socket/tcp_socket.h"
#include "../../common/utils/logging/logger.h"

namespace ft {
namespace server {

class ClientSession; // 前向声明

/**
 * @brief 协议处理器基类
 */
class ProtocolHandler {
public:
    /**
     * @brief 构造函数
     * @param session 客户端会话引用
     */
    explicit ProtocolHandler(ClientSession& session);
    
    /**
     * @brief 析构函数
     */
    virtual ~ProtocolHandler() = default;
    
    /**
     * @brief 处理协议消息
     * @param buffer 消息缓冲区
     * @return 是否处理成功
     */
    virtual bool handle(const std::vector<uint8_t>& buffer) = 0;

protected:
    /**
     * @brief 发送错误响应
     * @param error_message 错误消息
     * @return 是否发送成功
     */
    bool send_error_response(const std::string& error_message);
    
    /**
     * @brief 获取会话ID
     * @return 会话ID
     */
    size_t get_session_id() const;
    
    /**
     * @brief 获取socket引用
     * @return socket引用
     */
    network::TcpSocket& get_socket();
    
    /**
     * @brief 检查是否启用加密
     * @return 是否启用加密
     */
    bool is_encryption_enabled() const;
    
    /**
     * @brief 检查密钥交换是否完成
     * @return 是否完成
     */
    bool is_key_exchange_completed() const;
    
    /**
     * @brief 加密数据
     * @param data 待加密数据
     * @return 加密后的数据
     */
    std::vector<uint8_t> encrypt_data(const std::vector<uint8_t>& data);
    
    /**
     * @brief 解密数据
     * @param data 待解密数据
     * @return 解密后的数据
     */
    std::vector<uint8_t> decrypt_data(const std::vector<uint8_t>& data);

protected:
    ClientSession& session_;
};

} // namespace server
} // namespace ft 