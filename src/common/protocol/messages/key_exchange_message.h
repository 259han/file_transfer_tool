#pragma once

#include "../protocol.h"
#include <vector>
#include <string>

namespace ft {
namespace protocol {

/**
 * @brief 密钥交换阶段枚举
 */
enum class KeyExchangePhase : uint8_t {
    CLIENT_HELLO = 0x01,  // 客户端发送初始参数
    SERVER_HELLO = 0x02,  // 服务器响应
    COMPLETE = 0x03       // 交换完成确认
};

/**
 * @brief 密钥交换消息类
 */
class KeyExchangeMessage : public Message {
public:
    /**
     * @brief 构造函数-创建新的密钥交换消息
     * @param phase 密钥交换阶段
     */
    explicit KeyExchangeMessage(KeyExchangePhase phase = KeyExchangePhase::CLIENT_HELLO);
    
    /**
     * @brief 构造函数-从现有消息创建
     * @param msg 已有消息
     */
    explicit KeyExchangeMessage(const Message& msg);
    
    /**
     * @brief 设置密钥交换参数
     * @param params 密钥交换参数
     */
    void set_exchange_params(const std::vector<uint8_t>& params);
    
    /**
     * @brief 获取密钥交换参数
     * @return 密钥交换参数
     */
    std::vector<uint8_t> get_exchange_params() const;
    
    /**
     * @brief 设置交换阶段
     * @param phase 交换阶段
     */
    void set_exchange_phase(KeyExchangePhase phase);
    
    /**
     * @brief 获取交换阶段
     * @return 交换阶段
     */
    KeyExchangePhase get_exchange_phase() const;
    
private:
    void serialize();
    void deserialize();
    
    KeyExchangePhase phase_;             // 交换阶段
    std::vector<uint8_t> exchange_params_; // 交换参数
};

} // namespace protocol
} // namespace ft 