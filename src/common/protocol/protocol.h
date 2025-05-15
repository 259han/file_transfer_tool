#pragma once

#include "core/protocol_header.h"
#include <vector>
#include <string>

namespace ft {
namespace protocol {

/**
 * @brief 消息基类
 */
class Message {
public:
    /**
     * @brief 构造函数
     * @param type 操作类型
     */
    explicit Message(OperationType type = OperationType::HEARTBEAT);
    
    /**
     * @brief 析构函数
     */
    virtual ~Message();
    
    /**
     * @brief 编码消息到缓冲区
     * @param buffer 输出缓冲区
     * @return 成功返回true，失败返回false
     */
    virtual bool encode(std::vector<uint8_t>& buffer);
    
    /**
     * @brief 从缓冲区解码消息
     * @param buffer 输入缓冲区
     * @return 成功返回true，失败返回false
     */
    virtual bool decode(const std::vector<uint8_t>& buffer);
    
    /**
     * @brief 设置负载数据
     * @param data 数据指针
     * @param len 数据长度
     */
    void set_payload(const void* data, size_t len);
    
    /**
     * @brief 设置操作类型
     * @param type 操作类型
     */
    void set_operation_type(OperationType type);
    
    /**
     * @brief 设置标志位
     * @param flags 标志位
     */
    void set_flags(uint8_t flags);
    
    /**
     * @brief 获取操作类型
     * @return 操作类型
     */
    OperationType get_operation_type() const;
    
    /**
     * @brief 获取标志位
     * @return 标志位
     */
    uint8_t get_flags() const;
    
    /**
     * @brief 获取负载数据
     * @return 负载数据的引用
     */
    const std::vector<uint8_t>& get_payload() const;
    
protected:
    ProtocolHeader header_;
    std::vector<uint8_t> payload_;
};

} // namespace protocol
} // namespace ft 