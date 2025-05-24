#pragma once

#include <cstdint>
#include <cstddef>
#include <arpa/inet.h>

namespace ft {
namespace protocol {

/**
 * @brief 协议魔数，用于标识协议的开始
 */
constexpr uint32_t PROTOCOL_MAGIC = 0x12345678;

/**
 * @brief 操作类型枚举
 */
enum class OperationType : uint8_t {
    UPLOAD = 0x01,       // 上传操作
    DOWNLOAD = 0x02,     // 下载操作
    HEARTBEAT = 0x03,    // 心跳包
    KEY_EXCHANGE = 0x04, // 密钥交换
    AUTHENTICATION = 0x05, // 身份认证
    ERROR = 0xFF         // 错误响应
};

/**
 * @brief 协议标志位
 */
enum class ProtocolFlags : uint8_t {
    NONE = 0x00,         // 无特殊标志
    COMPRESSED = 0x01,   // 数据已压缩
    ENCRYPTED = 0x02,    // 数据已加密
    LAST_CHUNK = 0x04,   // 最后一个数据块
    RESUME = 0x08        // 断点续传
};

/**
 * @brief 64位整数网络字节序转换
 * @param value 主机字节序的64位整数
 * @return 网络字节序的64位整数
 */
inline uint64_t host_to_net64(uint64_t value) {
#if __BYTE_ORDER == __LITTLE_ENDIAN
    return ((uint64_t)htonl((uint32_t)value) << 32) | htonl((uint32_t)(value >> 32));
#else
    return value;
#endif
}

/**
 * @brief 64位整数主机字节序转换
 * @param value 网络字节序的64位整数
 * @return 主机字节序的64位整数
 */
inline uint64_t net_to_host64(uint64_t value) {
#if __BYTE_ORDER == __LITTLE_ENDIAN
    return ((uint64_t)ntohl((uint32_t)value) << 32) | ntohl((uint32_t)(value >> 32));
#else
    return value;
#endif
}

/**
 * @brief 协议头结构
 */
struct ProtocolHeader {
    uint32_t magic;        // 魔数：0x12345678
    uint8_t type;          // 操作类型
    uint8_t flags;         // 标志位
    uint32_t length;       // 数据长度
    uint32_t checksum;     // 校验和
    uint16_t reserved;     // 保留字段

    /**
     * @brief 初始化协议头
     * @param op 操作类型
     * @param flg 标志位
     * @param len 数据长度
     */
    ProtocolHeader(OperationType op = OperationType::HEARTBEAT, 
                  uint8_t flg = 0, 
                  uint32_t len = 0);
                  
    /**
     * @brief 计算校验和
     * @param data 数据指针
     * @param len 数据长度
     * @return 校验和值
     */
    static uint32_t calculate_checksum(const void* data, size_t len);
} __attribute__((packed));

} // namespace protocol
} // namespace ft 