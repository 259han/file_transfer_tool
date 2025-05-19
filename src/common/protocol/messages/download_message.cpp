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
        LOG_WARNING("Invalid operation type for DownloadMessage: %d", 
                   static_cast<int>(get_operation_type()));
        return;
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
        set_flags(get_flags() | static_cast<uint8_t>(ProtocolFlags::LAST_CHUNK));
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
    
    // 序列化偏移量和长度 - 转换为网络字节序
    uint64_t offset_be = host_to_net64(offset_);
    uint64_t length_be = host_to_net64(length_);
    std::memcpy(payload.data() + sizeof(uint32_t) + filename_.size(), &offset_be, sizeof(uint64_t));
    std::memcpy(payload.data() + sizeof(uint32_t) + filename_.size() + sizeof(uint64_t), &length_be, sizeof(uint64_t));
    
    // 设置负载
    set_payload(payload.data(), payload.size());
    
    LOG_DEBUG("Serialized download request: filename='%s', offset=%llu, length=%llu, payload_size=%zu", 
             filename_.c_str(), offset_, length_, payload.size());
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
    
    // 确保LAST_CHUNK标志（如果这是最后一个分块）被保留
    // 不要在这里设置标志位，因为这会覆盖之前在set_response_data中设置的标志
    
    // 调试输出
    LOG_DEBUG("serialize_response: offset=%llu, total_size=%llu, data_size=%zu, last_chunk=%d, flags=%u", 
             offset_, total_size_, response_data_.size(), 
             is_last_chunk() ? 1 : 0, get_flags());
}

void DownloadMessage::deserialize() {
    const std::vector<uint8_t>& payload = get_payload();
    if (payload.empty()) {
        LOG_WARNING("DownloadMessage::deserialize: Empty payload");
        return;
    }

    // 首先检查标志位，确定是请求还是响应
    uint8_t flags_value = get_flags();
    
    // 通过操作类型和标志位判断是否为响应消息
    bool has_last_chunk_flag = (flags_value & static_cast<uint8_t>(ProtocolFlags::LAST_CHUNK)) != 0;
    bool has_encrypted_flag = (flags_value & static_cast<uint8_t>(ProtocolFlags::ENCRYPTED)) != 0;
    
    LOG_DEBUG("DownloadMessage::deserialize: Analyzing message: flags=0x%02x, payload_size=%zu, operation_type=%d", 
             flags_value, payload.size(), static_cast<int>(get_operation_type()));
    
    // 打印前几个字节用于调试
    if (payload.size() > 0) {
        std::string data_preview;
        for (size_t i = 0; i < std::min(payload.size(), size_t(16)); ++i) {
            char hex[4];
            snprintf(hex, sizeof(hex), "%02x ", payload[i]);
            data_preview += hex;
        }
        LOG_DEBUG("DownloadMessage::deserialize: Payload preview: %s", data_preview.c_str());
    }
    
    // 更严格的消息类型识别逻辑
    // 首先检查LAST_CHUNK标志，如果设置，则肯定是响应消息
    if (has_last_chunk_flag) {
        // 响应消息格式：|offset(8)|total_size(8)|data(...)|
        if (payload.size() >= sizeof(uint64_t) * 2) {
            uint64_t possible_offset, possible_total_size;
            std::memcpy(&possible_offset, payload.data(), sizeof(uint64_t));
            std::memcpy(&possible_total_size, payload.data() + sizeof(uint64_t), sizeof(uint64_t));
            
            // 转换为主机字节序
            uint64_t host_offset = net_to_host64(possible_offset);
            uint64_t host_total_size = net_to_host64(possible_total_size);
            
            // 标记为响应消息
            is_request_ = false;
            offset_ = host_offset;
            total_size_ = host_total_size;
            
            // 提取响应数据
            size_t metadata_size = sizeof(uint64_t) * 2;
            response_data_.clear();
            if (payload.size() > metadata_size) {
                response_data_.assign(payload.begin() + metadata_size, payload.end());
            }
            
            LOG_DEBUG("Deserialized download response (with LAST_CHUNK flag): offset=%llu, total_size=%llu, data_size=%zu, last_chunk=%d",
                     offset_, total_size_, response_data_.size(), has_last_chunk_flag ? 1 : 0);
            return;
        }
    }
    
    // 检查请求消息的标记 - 第一个字段应该是一个4字节的文件名长度（uint32_t）
    // 请求消息格式：|filename_len(4)|filename(...)|offset(8)|length(8)|
    if (payload.size() >= sizeof(uint32_t)) {
        uint32_t filename_len = 0;
        std::memcpy(&filename_len, payload.data(), sizeof(uint32_t));
        
        // 检查文件名长度是否合理 (小于payload大小且不太大)
        // 更严格的限制，防止误识别
        if (filename_len < 1024 && 
            sizeof(uint32_t) + filename_len + sizeof(uint64_t) * 2 <= payload.size()) {
            
            // 读取文件名
            std::string temp_filename;
            if (filename_len > 0) {
                temp_filename = std::string(reinterpret_cast<const char*>(payload.data() + sizeof(uint32_t)), filename_len);
                
                // 检查文件名有效性（不应包含控制字符）
                bool valid_filename = true;
                for (char c : temp_filename) {
                    if (c < 32 || c > 126) {
                        valid_filename = false;
                        break;
                    }
                }
                
                if (!valid_filename) {
                    LOG_WARNING("Invalid characters in filename, not treating as request message");
                    goto try_response; // 尝试作为响应消息解析
                }
            }
            
            // 这可能是一个请求消息
            is_request_ = true;
            filename_ = temp_filename;
            
            // 读取偏移量和长度
            size_t offset_pos = sizeof(uint32_t) + filename_len;
            std::memcpy(&offset_, payload.data() + offset_pos, sizeof(uint64_t));
            std::memcpy(&length_, payload.data() + offset_pos + sizeof(uint64_t), sizeof(uint64_t));
            
            // 字节序转换
            offset_ = net_to_host64(offset_);
            length_ = net_to_host64(length_);
            
            // 额外检查：偏移量和长度应该是合理的值
            if (offset_ > (1ULL << 40) || length_ > (1ULL << 40)) {
                LOG_WARNING("Unreasonable offset (%llu) or length (%llu) in request, not treating as request message", offset_, length_);
                goto try_response; // 尝试作为响应消息解析
            }
            
            LOG_DEBUG("Deserialized download request: filename='%s', offset=%llu, length=%llu, encrypted=%d",
                     filename_.c_str(), offset_, length_, has_encrypted_flag ? 1 : 0);
            return;
        }
    }
    
try_response:
    // 如果不是请求消息，则尝试解析为响应消息
    // 响应消息格式：|offset(8)|total_size(8)|data(...)|
    if (payload.size() >= sizeof(uint64_t) * 2) {
        uint64_t possible_offset, possible_total_size;
        std::memcpy(&possible_offset, payload.data(), sizeof(uint64_t));
        std::memcpy(&possible_total_size, payload.data() + sizeof(uint64_t), sizeof(uint64_t));
        
        // 转换为主机字节序
        uint64_t host_offset = net_to_host64(possible_offset);
        uint64_t host_total_size = net_to_host64(possible_total_size);
        
        // 额外检查：偏移量和总大小应该是合理的值
        if (host_offset > (1ULL << 40) || host_total_size > (1ULL << 40)) {
            LOG_WARNING("Unreasonable offset (%llu) or total_size (%llu) in response", host_offset, host_total_size);
            goto parse_failed; // 解析失败
        }
        
        // 标记为响应消息
        is_request_ = false;
        offset_ = host_offset;
        total_size_ = host_total_size;
        
        // 提取响应数据
        size_t metadata_size = sizeof(uint64_t) * 2;
        response_data_.clear();
        if (payload.size() > metadata_size) {
            response_data_.assign(payload.begin() + metadata_size, payload.end());
        }
        
        LOG_DEBUG("Deserialized download response: offset=%llu, total_size=%llu, data_size=%zu, last_chunk=%d",
                 offset_, total_size_, response_data_.size(), has_last_chunk_flag ? 1 : 0);
        return;
    }
    
parse_failed:
    // 如果到这里，说明无法正确解析消息
    LOG_WARNING("DownloadMessage::deserialize: Failed to parse message, unknown format");
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

void DownloadMessage::set_offset(uint64_t offset) {
    offset_ = offset;
    if (!is_request_) {
        serialize_response();
    }
}

} // namespace protocol
} // namespace ft 