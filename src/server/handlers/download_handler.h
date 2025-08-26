#pragma once

#include "protocol_handler.h"

namespace ft {
namespace protocol {
    class DownloadMessage; // 前向声明
}

namespace server {

/**
 * @brief 下载处理器
 * 负责处理客户端的文件下载请求
 */
class DownloadHandler : public ProtocolHandler {
public:
    /**
     * @brief 构造函数
     * @param session 客户端会话引用
     */
    explicit DownloadHandler(ClientSession& session);
    
    /**
     * @brief 析构函数
     */
    ~DownloadHandler() override = default;
    
    /**
     * @brief 处理下载消息
     * @param buffer 消息缓冲区
     * @return 是否处理成功
     */
    bool handle(const std::vector<uint8_t>& buffer) override;

private:
    /**
     * @brief 处理下载请求
     * @param download_msg 下载消息
     * @return 是否处理成功
     */
    bool process_download_request(const protocol::DownloadMessage& download_msg);

    bool send_file_data(const std::string& file_path, uint64_t offset, uint64_t length);

    bool send_data_chunk(const std::vector<uint8_t>& data, uint64_t offset,
                         uint64_t total_size, bool is_last_chunk);
    
    /**
     * @brief 使用零拷贝技术发送文件
     * @param file_path 文件路径
     * @param offset 偏移量
     * @param length 读取长度
     * @param total_size 文件总大小
     * @return 是否发送成功
     */
    bool send_file_with_zero_copy(const std::string& file_path, uint64_t offset, uint64_t length, uint64_t total_size);
    
    /**
     * @brief 使用混合加密策略发送大文件
     * @param file_path 文件路径
     * @param offset 偏移量
     * @param length 读取长度
     * @param total_size 文件总大小
     * @return 是否发送成功
     */
    bool send_file_with_hybrid_encryption(const std::string& file_path, uint64_t offset, uint64_t length, uint64_t total_size);
    
    /**
     * @brief 发送加密的文件块
     * @param fd 文件描述符
     * @param offset 偏移量
     * @param length 读取长度
     * @param is_critical 是否为关键数据
     * @return 是否发送成功
     */
    bool send_encrypted_chunk(int fd, uint64_t offset, uint64_t length, bool is_critical);
    
    /**
     * @brief 发送错误响应
     * @param error_msg 错误消息
     * @return 始终返回false
     */
    bool send_error_response(const std::string& error_msg);
};

} // namespace server
} // namespace ft 