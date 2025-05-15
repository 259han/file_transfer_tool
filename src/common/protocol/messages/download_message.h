#pragma once

#include "../protocol.h"
#include <string>

namespace ft {
namespace protocol {

/**
 * @brief 下载消息
 */
class DownloadMessage : public Message {
public:
    /**
     * @brief 构造函数
     * @param filename 文件名
     * @param offset 文件偏移量
     * @param length 请求的长度
     */
    DownloadMessage(const std::string& filename = "", 
                   uint64_t offset = 0, 
                   uint64_t length = 0);
    
    /**
     * @brief 从消息对象解析下载消息
     * @param msg 消息对象
     */
    explicit DownloadMessage(const Message& msg);
    
    /**
     * @brief 设置响应数据
     * @param data 数据指针
     * @param size 数据大小
     * @param total_size 文件总大小
     * @param last_chunk 是否为最后一个块
     */
    void set_response_data(const void* data, size_t size, uint64_t total_size, bool last_chunk);
    
    /**
     * @brief 获取文件名
     * @return 文件名
     */
    std::string get_filename() const;
    
    /**
     * @brief 获取文件偏移量
     * @return 文件偏移量
     */
    uint64_t get_offset() const;
    
    /**
     * @brief 获取请求的长度
     * @return 请求的长度
     */
    uint64_t get_length() const;
    
    /**
     * @brief 获取文件总大小
     * @return 文件总大小
     */
    uint64_t get_total_size() const;
    
    /**
     * @brief 是否为最后一个块
     * @return 是否为最后一个块
     */
    bool is_last_chunk() const;
    
    /**
     * @brief 获取响应数据
     * @return 响应数据的引用
     */
    const std::vector<uint8_t>& get_response_data() const;
    
    /**
     * @brief 是否为请求消息
     * @return 是否为请求消息
     */
    bool is_request() const;
    
private:
    /**
     * @brief 序列化请求
     */
    void serialize_request();
    
    /**
     * @brief 序列化响应
     */
    void serialize_response();
    
    /**
     * @brief 反序列化
     */
    void deserialize();
    
private:
    std::string filename_;
    uint64_t offset_;
    uint64_t length_;
    uint64_t total_size_;
    std::vector<uint8_t> response_data_;
    bool is_request_;
};

} // namespace protocol
} // namespace ft 