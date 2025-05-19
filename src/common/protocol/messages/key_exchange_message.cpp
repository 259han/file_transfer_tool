#include "key_exchange_message.h"
#include <cstring>
#include <stdexcept>

namespace ft {
namespace protocol {

KeyExchangeMessage::KeyExchangeMessage(KeyExchangePhase phase)
    : Message(OperationType::KEY_EXCHANGE), 
      phase_(phase),
      exchange_params_() {
    serialize();
}

KeyExchangeMessage::KeyExchangeMessage(const Message& msg)
    : Message(msg),
      phase_(KeyExchangePhase::CLIENT_HELLO),
      exchange_params_() {
    
    // 检查操作类型
    if (get_operation_type() != OperationType::KEY_EXCHANGE) {
        throw std::runtime_error("Invalid operation type for KeyExchangeMessage");
    }
    
    deserialize();
}

void KeyExchangeMessage::set_exchange_params(const std::vector<uint8_t>& params) {
    exchange_params_ = params;
    serialize();
}

std::vector<uint8_t> KeyExchangeMessage::get_exchange_params() const {
    return exchange_params_;
}

void KeyExchangeMessage::set_exchange_phase(KeyExchangePhase phase) {
    phase_ = phase;
    serialize();
}

KeyExchangePhase KeyExchangeMessage::get_exchange_phase() const {
    return phase_;
}

void KeyExchangeMessage::serialize() {
    // 计算负载大小: 1字节的阶段 + 参数数据
    size_t payload_size = 1 + exchange_params_.size();
    
    // 创建负载缓冲区
    std::vector<uint8_t> payload(payload_size);
    
    // 写入阶段
    payload[0] = static_cast<uint8_t>(phase_);
    
    // 写入参数
    if (!exchange_params_.empty()) {
        std::memcpy(payload.data() + 1, exchange_params_.data(), exchange_params_.size());
    }
    
    // 设置负载
    set_payload(payload.data(), payload.size());
}

void KeyExchangeMessage::deserialize() {
    const std::vector<uint8_t>& payload = get_payload();
    if (payload.empty()) {
        return;
    }
    
    // 读取阶段
    phase_ = static_cast<KeyExchangePhase>(payload[0]);
    
    // 读取参数
    if (payload.size() > 1) {
        exchange_params_.resize(payload.size() - 1);
        std::memcpy(exchange_params_.data(), payload.data() + 1, payload.size() - 1);
    } else {
        exchange_params_.clear();
    }
}

} // namespace protocol
} // namespace ft 