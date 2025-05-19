#include "download_message.h"
#include <cstring>
#include <stdexcept>
#include <string>
#include <sstream>
#include "../../utils/logging/logger.h"

namespace ft {
namespace protocol {

DownloadMessage::DownloadMessage(const std::string& filename, uint64_t offset, uint64_t length, bool is_request)
    : Message(OperationType::DOWNLOAD), 
      filename_(filename),
      offset_(offset),
      length_(length),
      total_size_(0),
      response_data_(),
      is_request_(is_request),
      encrypted_(false) {
    
    // 序列化请求
    if (is_request_) {
        serialize_request();
    }
}

DownloadMessage::DownloadMessage(const Message& msg)
    : Message(msg), 
      filename_(""),
      offset_(0),
      length_(0),
      total_size_(0),
      response_data_(),
      is_request_(false),
      encrypted_(false) {
    
    // 检查操作类型
    if (get_operation_type() != OperationType::DOWNLOAD) {
        throw std::runtime_error("Invalid operation type for DownloadMessage");
    }
    
    // 反序列化
    deserialize();
}

void DownloadMessage::set_response_data(const void* data, size_t size, uint64_t total_size, bool last_chunk) {
    // 设置为响应消息
    is_request_ = false;
    
    // 保存响应数据和文件总大小
    response_data_.resize(size);
    if (size > 0) {
        std::memcpy(response_data_.data(), data, size);
    }
    total_size_ = total_size;
    
    // 设置标志位
    if (last_chunk) {
        set_flags(static_cast<uint8_t>(ProtocolFlags::LAST_CHUNK));
    }
    
    // 序列化响应
    serialize_response();
    
    LOG_DEBUG("Set response data: size=%zu, total_size=%llu, last_chunk=%d, flags=%u", 
             size, total_size, last_chunk ? 1 : 0, get_flags());
}

std::string DownloadMessage::get_filename() const {
    return filename_;
}

uint64_t DownloadMessage::get_offset() const {
    return offset_;
}

uint64_t DownloadMessage::get_length() const {
    return length_;
}

uint64_t DownloadMessage::get_total_size() const {
    return total_size_;
}

bool DownloadMessage::is_last_chunk() const {
    return (get_flags() & static_cast<uint8_t>(ProtocolFlags::LAST_CHUNK)) != 0;
}

const std::vector<uint8_t>& DownloadMessage::get_response_data() const {
    return response_data_;
}

bool DownloadMessage::is_request() const {
    return is_request_;
}

void DownloadMessage::serialize_request() {
    // 计算元数据大小
    size_t metadata_size = sizeof(uint64_t) * 2 + sizeof(uint32_t) + filename_.size();
    
    // 创建负载缓冲区
    std::vector<uint8_t> payload(metadata_size);
    
    // 序列化文件名
    uint32_t filename_len = static_cast<uint32_t>(filename_.size());
    std::memcpy(payload.data(), &filename_len, sizeof(uint32_t));
    std::memcpy(payload.data() + sizeof(uint32_t), filename_.data(), filename_.size());
    
    // 序列化偏移量和长度
    std::memcpy(payload.data() + sizeof(uint32_t) + filename_.size(), &offset_, sizeof(uint64_t));
    std::memcpy(payload.data() + sizeof(uint32_t) + filename_.size() + sizeof(uint64_t), &length_, sizeof(uint64_t));
    
    // 设置负载
    set_payload(payload.data(), payload.size());
}

void DownloadMessage::serialize_response() {
    // 计算元数据大小
    size_t metadata_size = sizeof(uint64_t) * 2;
    
    // 计算总的负载大小(元数据+响应数据)
    size_t payload_size = metadata_size + response_data_.size();
    
    // 创建负载缓冲区
    std::vector<uint8_t> payload(payload_size);
    
    // 序列化偏移量和文件总大小 - 使用网络字节序（大端序）
    uint64_t offset_be = host_to_net64(offset_);
    uint64_t total_size_be = host_to_net64(total_size_);
    std::memcpy(payload.data(), &offset_be, sizeof(uint64_t));
    std::memcpy(payload.data() + sizeof(uint64_t), &total_size_be, sizeof(uint64_t));
    
    // 添加响应数据
    if (!response_data_.empty()) {
        std::memcpy(payload.data() + metadata_size, response_data_.data(), response_data_.size());
    }
    
    // 设置负载
    set_payload(payload.data(), payload.size());
    
    // 调试输出
    LOG_DEBUG("serialize_response: offset=%llu, total_size=%llu, data_size=%zu, last_chunk=%d", 
             offset_, total_size_, response_data_.size(), 
             (get_flags() & static_cast<uint8_t>(ProtocolFlags::LAST_CHUNK)) ? 1 : 0);
}

void DownloadMessage::deserialize() {
    const std::vector<uint8_t>& payload = get_payload();
    if (payload.empty()) {
        LOG_WARNING("DownloadMessage::deserialize: Empty payload");
        return;
    }

    // 首先判断是否为响应消息（通过检查操作类型和标志位）
    if ((get_flags() & static_cast<uint8_t>(ProtocolFlags::LAST_CHUNK)) != 0) {
        // 这是一个响应消息
        is_request_ = false;
        
        // 如果负载大小至少包含偏移量和总大小
        if (payload.size() >= sizeof(uint64_t) * 2) {
            // 解析偏移量和总大小 - 从网络字节序（大端序）转换
            uint64_t offset_be = 0;
            uint64_t total_size_be = 0;
            std::memcpy(&offset_be, payload.data(), sizeof(uint64_t));
            std::memcpy(&total_size_be, payload.data() + sizeof(uint64_t), sizeof(uint64_t));
            
            // 转换为主机字节序
            offset_ = net_to_host64(offset_be);
            total_size_ = net_to_host64(total_size_be);
            
            // 提取响应数据
            size_t metadata_size = sizeof(uint64_t) * 2;
            size_t response_data_size = payload.size() - metadata_size;
            
            LOG_DEBUG("Deserialized download response: offset=%llu, total_size=%llu, data_size=%zu, flags=%u", 
                     offset_, total_size_, response_data_size, get_flags());
            
            if (response_data_size > 0) {
                response_data_.resize(response_data_size);
                std::memcpy(response_data_.data(), payload.data() + metadata_size, response_data_size);
                
                // 显示响应数据的前几个字节
                std::string data_preview;
                for (size_t i = 0; i < std::min(response_data_size, size_t(16)); ++i) {
                    char hex[4];
                    snprintf(hex, sizeof(hex), "%02x ", response_data_[i]);
                    data_preview += hex;
                }
                LOG_DEBUG("Response data preview: %s", data_preview.c_str());
            } else {
                LOG_DEBUG("Response contains no data payload (empty file or metadata only)");
                response_data_.clear();
            }
            return;
        } else {
            LOG_WARNING("Invalid download response: payload too small (%zu bytes)", payload.size());
            return;
        }
    }
    
    // 如果不是响应消息，则尝试解析为请求消息
    if (payload.size() >= sizeof(uint32_t)) {
        uint32_t filename_len = 0;
        std::memcpy(&filename_len, payload.data(), sizeof(uint32_t));
        
        LOG_DEBUG("DownloadMessage::deserialize: Request detected, filename_len=%u", filename_len);
        
        // 如果负载大小符合请求消息的格式，则认为是请求消息
        if (payload.size() >= sizeof(uint32_t) + filename_len + sizeof(uint64_t) * 2) {
            is_request_ = true;
            
            // 解析文件名
            if (filename_len > 0) {
                filename_.resize(filename_len);
                std::memcpy(&filename_[0], payload.data() + sizeof(uint32_t), filename_len);
            }
            
            // 解析偏移量和长度
            std::memcpy(&offset_, payload.data() + sizeof(uint32_t) + filename_len, sizeof(uint64_t));
            std::memcpy(&length_, payload.data() + sizeof(uint32_t) + filename_len + sizeof(uint64_t), sizeof(uint64_t));
            
            LOG_DEBUG("Deserialized download request: filename=%s, offset=%llu, length=%llu", 
                     filename_.c_str(), offset_, length_);
            return;
        }
    }
    
    LOG_WARNING("Failed to deserialize download message: unrecognized format, payload size=%zu", payload.size());
}

void DownloadMessage::set_encrypted(bool encrypted) {
    encrypted_ = encrypted;
    
    // 如果启用加密，设置加密标志
    if (encrypted) {
        set_flags(get_flags() | static_cast<uint8_t>(ProtocolFlags::ENCRYPTED));
    } else {
        set_flags(get_flags() & ~static_cast<uint8_t>(ProtocolFlags::ENCRYPTED));
    }
    
    // 更新元数据
    if (is_request_) {
        serialize_request();
    } else {
        serialize_response();
    }
}

bool DownloadMessage::is_encrypted() const {
    return (get_flags() & static_cast<uint8_t>(ProtocolFlags::ENCRYPTED)) != 0;
}

void DownloadMessage::set_file_data(const std::vector<uint8_t>& data) {
    response_data_ = data;
    serialize_response();
}

std::vector<uint8_t> DownloadMessage::get_file_data() const {
    return response_data_;
}

void DownloadMessage::set_total_size(uint64_t size) {
    total_size_ = size;
    if (!is_request_) {
        serialize_response();
    }
}

void DownloadMessage::parse_metadata() {
    // 从负载中提取元数据
    // 这是一个示例实现，需要根据实际协议格式调整
}

void DownloadMessage::update_metadata() {
    // 更新负载中的元数据
    // 这是一个示例实现，需要根据实际协议格式调整
}

} // namespace protocol
} // namespace ft 