#pragma once

#include "../protocol.h"
#include <string>

namespace ft {
namespace protocol {

/**
 * @brief 上传消息
 */
class UploadMessage : public Message {
public:
    /**
     * @brief 构造函数
     * @param filename 文件名
     * @param offset 文件偏移量
     * @param total_size 文件总大小
     * @param last_chunk 是否为最后一个块
     */
    UploadMessage(const std::string& filename = "", 
                  uint64_t offset = 0, 
                  uint64_t total_size = 0,
                  bool last_chunk = false);
    
    /**
     * @brief 从消息对象解析上传消息
     * @param msg 消息对象
     */
    explicit UploadMessage(const Message& msg);
    
    /**
     * @brief 设置文件数据
     * @param data 数据指针
     * @param size 数据大小
     */
    void set_file_data(const void* data, size_t size);
    
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
     * @brief 获取文件数据
     * @return 文件数据的引用
     */
    const std::vector<uint8_t>& get_file_data() const;
    
private:
    /**
     * @brief 序列化元数据
     */
    void serialize_metadata();
    
    /**
     * @brief 反序列化元数据
     */
    void deserialize_metadata();
    
private:
    std::string filename_;
    uint64_t offset_;
    uint64_t total_size_;
    std::vector<uint8_t> file_data_;
};

} // namespace protocol
} // namespace ft 