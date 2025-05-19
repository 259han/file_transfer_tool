#include "upload_message.h"
#include <cstring>
#include <stdexcept>
#include <string>
#include "../../utils/logging/logger.h"

namespace ft {
namespace protocol {

UploadMessage::UploadMessage(const std::string& filename, uint64_t offset, uint64_t total_size, bool last_chunk)
    : Message(OperationType::UPLOAD), 
      filename_(filename),
      offset_(offset),
      total_size_(total_size),
      file_data_(),
      encrypted_(false) {
    // 设置标志位
    if (last_chunk) {
        set_flags(static_cast<uint8_t>(ProtocolFlags::LAST_CHUNK));
    }
    
    // 序列化元数据
    serialize_metadata();
    
    LOG_DEBUG("Created upload message: filename=%s, offset=%llu, total_size=%llu, last_chunk=%d", 
              filename.c_str(), offset, total_size, last_chunk ? 1 : 0);
}

UploadMessage::UploadMessage(const Message& msg)
    : Message(msg), 
      filename_(""),
      offset_(0),
      total_size_(0),
      file_data_(),
      encrypted_(false) {
    // 检查操作类型
    if (get_operation_type() != OperationType::UPLOAD) {
        // 记录错误但不抛异常，让调用者检查消息类型
        LOG_WARNING("Invalid operation type for UploadMessage: %d", 
                    static_cast<int>(get_operation_type()));
        return;
    }
    
    // 反序列化元数据
    deserialize_metadata();
}

void UploadMessage::set_file_data(const void* data, size_t size) {
    // 保存文件数据
    file_data_.resize(size);
    if (size > 0) {
        std::memcpy(file_data_.data(), data, size);
    }
    
    // 重新序列化元数据和文件数据
    serialize_metadata();
    
    LOG_DEBUG("Set file data: size=%zu, filename=%s", size, filename_.c_str());
}

std::string UploadMessage::get_filename() const {
    return filename_;
}

uint64_t UploadMessage::get_offset() const {
    return offset_;
}

uint64_t UploadMessage::get_total_size() const {
    return total_size_;
}

bool UploadMessage::is_last_chunk() const {
    return (get_flags() & static_cast<uint8_t>(ProtocolFlags::LAST_CHUNK)) != 0;
}

const std::vector<uint8_t>& UploadMessage::get_file_data() const {
    return file_data_;
}

void UploadMessage::serialize_metadata() {
    // 计算元数据大小
    size_t metadata_size = sizeof(uint64_t) * 2 + sizeof(uint32_t) + filename_.size();
    
    // 计算总的负载大小(元数据+文件数据)
    size_t payload_size = metadata_size + file_data_.size();
    
    // 创建负载缓冲区
    std::vector<uint8_t> payload(payload_size);
    
    // 序列化文件名
    uint32_t filename_len = static_cast<uint32_t>(filename_.size());
    std::memcpy(payload.data(), &filename_len, sizeof(uint32_t));
    std::memcpy(payload.data() + sizeof(uint32_t), filename_.data(), filename_.size());
    
    // 序列化偏移量和总大小 - 使用网络字节序（大端序）
    uint64_t offset_be = host_to_net64(offset_);
    uint64_t total_size_be = host_to_net64(total_size_);
    std::memcpy(payload.data() + sizeof(uint32_t) + filename_.size(), &offset_be, sizeof(uint64_t));
    std::memcpy(payload.data() + sizeof(uint32_t) + filename_.size() + sizeof(uint64_t), &total_size_be, sizeof(uint64_t));
    
    // 添加文件数据
    if (!file_data_.empty()) {
        std::memcpy(payload.data() + metadata_size, file_data_.data(), file_data_.size());
    }
    
    // 设置负载
    set_payload(payload.data(), payload.size());
    
    LOG_DEBUG("Serialized upload message: filename=%s, metadata_size=%zu, data_size=%zu, total_size=%zu", 
              filename_.c_str(), metadata_size, file_data_.size(), payload_size);
}

void UploadMessage::deserialize_metadata() {
    const std::vector<uint8_t>& payload = get_payload();
    if (payload.empty()) {
        LOG_WARNING("UploadMessage::deserialize_metadata: Empty payload");
        return;
    }
    
    // 确保payload至少包含头部大小
    if (payload.size() < sizeof(uint32_t)) {
        LOG_WARNING("UploadMessage::deserialize_metadata: Payload too small (%zu bytes)", payload.size());
        return;
    }
    
    // 解析文件名
    uint32_t filename_len = 0;
    std::memcpy(&filename_len, payload.data(), sizeof(uint32_t));
    
    // 验证文件名长度
    if (filename_len > payload.size() - sizeof(uint32_t)) {
        LOG_WARNING("UploadMessage::deserialize_metadata: Invalid filename length (%u bytes)", filename_len);
        return;
    }
    
    if (filename_len > 0) {
        filename_.resize(filename_len);
        std::memcpy(&filename_[0], payload.data() + sizeof(uint32_t), filename_len);
    }
    
    // 确保payload至少包含文件名和其他元数据
    size_t metadata_min_size = sizeof(uint32_t) + filename_len + sizeof(uint64_t) * 2;
    if (payload.size() < metadata_min_size) {
        LOG_WARNING("UploadMessage::deserialize_metadata: Payload too small for offset and total_size (%zu bytes)", payload.size());
        return;
    }
    
    // 解析偏移量和总大小 - 从网络字节序（大端序）转换
    uint64_t offset_be = 0;
    uint64_t total_size_be = 0;
    std::memcpy(&offset_be, payload.data() + sizeof(uint32_t) + filename_len, sizeof(uint64_t));
    std::memcpy(&total_size_be, payload.data() + sizeof(uint32_t) + filename_len + sizeof(uint64_t), sizeof(uint64_t));
    
    // 转换为主机字节序
    offset_ = net_to_host64(offset_be);
    total_size_ = net_to_host64(total_size_be);
    
    // 计算元数据大小
    size_t metadata_size = sizeof(uint64_t) * 2 + sizeof(uint32_t) + filename_len;
    
    // 提取文件数据
    size_t file_data_size = payload.size() - metadata_size;
    if (file_data_size > 0) {
        file_data_.resize(file_data_size);
        std::memcpy(file_data_.data(), payload.data() + metadata_size, file_data_size);
        
        // 显示文件数据的前几个字节（用于调试）
        if (file_data_size > 0) {
            std::string data_preview;
            for (size_t i = 0; i < std::min(file_data_size, size_t(16)); ++i) {
                char hex[4];
                snprintf(hex, sizeof(hex), "%02x ", file_data_[i]);
                data_preview += hex;
            }
            LOG_DEBUG("File data preview: %s", data_preview.c_str());
        }
    }
    
    LOG_DEBUG("Deserialized upload message: filename=%s, offset=%llu, total_size=%llu, data_size=%zu", 
              filename_.c_str(), offset_, total_size_, file_data_size);
}

void UploadMessage::set_encrypted(bool encrypted) {
    encrypted_ = encrypted;
    
    // 如果启用加密，设置加密标志
    if (encrypted) {
        set_flags(get_flags() | static_cast<uint8_t>(ProtocolFlags::ENCRYPTED));
    } else {
        set_flags(get_flags() & ~static_cast<uint8_t>(ProtocolFlags::ENCRYPTED));
    }
    
    // 更新元数据
    serialize_metadata();
    
    LOG_DEBUG("Set encrypted flag: %d for file: %s", encrypted ? 1 : 0, filename_.c_str());
}

bool UploadMessage::is_encrypted() const {
    return (get_flags() & static_cast<uint8_t>(ProtocolFlags::ENCRYPTED)) != 0;
}

void UploadMessage::parse_metadata() {
    // 从负载中提取元数据
    // 这是一个示例实现，需要根据实际协议格式调整
    LOG_DEBUG("UploadMessage::parse_metadata called");
}

void UploadMessage::update_metadata() {
    // 更新负载中的元数据
    // 这是一个示例实现，需要根据实际协议格式调整
    LOG_DEBUG("UploadMessage::update_metadata called");
}

} // namespace protocol
} // namespace ft 