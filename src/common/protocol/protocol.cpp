#include "protocol.h"
#include <cstring>
#include "../../common/utils/logging/logger.h"

namespace ft {
namespace protocol {

Message::Message(OperationType type)
    : header_(type) {
}

Message::~Message() = default;

bool Message::encode(std::vector<uint8_t>& buffer) {
    // 确保缓冲区足够大
    buffer.resize(sizeof(ProtocolHeader) + payload_.size());
    
    // 确保魔数正确
    header_.magic = PROTOCOL_MAGIC;
    
    // 设置消息长度
    header_.length = static_cast<uint32_t>(payload_.size());
    
    // 计算校验和
    if (!payload_.empty()) {
        header_.checksum = ProtocolHeader::calculate_checksum(payload_.data(), payload_.size());
    } else {
        header_.checksum = 0;
    }
    
    // 拷贝消息头
    std::memcpy(buffer.data(), &header_, sizeof(ProtocolHeader));
    
    // 拷贝负载数据
    if (!payload_.empty()) {
        std::memcpy(buffer.data() + sizeof(ProtocolHeader), payload_.data(), payload_.size());
    }
    
    // 创建临时变量保存packed结构体的值
    uint32_t length = header_.length;
    uint32_t checksum = header_.checksum;
    
    LOG_DEBUG("Message encoded: type=%d, length=%u, checksum=0x%x", 
              static_cast<int>(get_operation_type()), length, checksum);
    
    return true;
}

bool Message::decode(const std::vector<uint8_t>& buffer) {
    if (buffer.size() < sizeof(ProtocolHeader)) {
        LOG_WARNING("Message decode failed: buffer too small (%zu bytes)", buffer.size());
        return false;
    }
    
    // 拷贝消息头
    std::memcpy(&header_, buffer.data(), sizeof(ProtocolHeader));
    
    // 创建临时变量保存packed结构体的值
    uint32_t magic = header_.magic;
    uint32_t length = header_.length;
    uint32_t checksum = header_.checksum;
    
    // 检查魔数
    if (magic != PROTOCOL_MAGIC) {
        LOG_WARNING("Message decode failed: invalid magic number (0x%x)", magic);
        return false;
    }
    
    // 检查长度
    if (buffer.size() != sizeof(ProtocolHeader) + length) {
        LOG_WARNING("Message decode failed: buffer size mismatch (expected %zu, got %zu)", 
                   sizeof(ProtocolHeader) + length, buffer.size());
        return false;
    }
    
    // 提取负载数据
    if (length > 0) {
        payload_.resize(length);
        std::memcpy(payload_.data(), buffer.data() + sizeof(ProtocolHeader), length);
        
        // 校验数据完整性
        uint32_t calculated_checksum = ProtocolHeader::calculate_checksum(payload_.data(), payload_.size());
        if (calculated_checksum != checksum) {
            LOG_WARNING("Message decode failed: checksum mismatch (expected 0x%x, calculated 0x%x)", 
                       checksum, calculated_checksum);
            return false;
        }
    } else {
        payload_.clear();
    }
    
    LOG_DEBUG("Message decoded: type=%d, length=%u, checksum=0x%x", 
              static_cast<int>(get_operation_type()), length, checksum);
    
    return true;
}

void Message::set_payload(const void* data, size_t len) {
    payload_.resize(len);
    if (len > 0) {
        std::memcpy(payload_.data(), data, len);
    }
}

void Message::set_operation_type(OperationType type) {
    header_.type = static_cast<uint8_t>(type);
}

void Message::set_flags(uint8_t flags) {
    header_.flags = flags;
}

OperationType Message::get_operation_type() const {
    return static_cast<OperationType>(header_.type);
}

uint8_t Message::get_flags() const {
    return header_.flags;
}

const std::vector<uint8_t>& Message::get_payload() const {
    return payload_;
}

} // namespace protocol
} // namespace ft 