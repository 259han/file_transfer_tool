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
    
    /**
     * @brief 发送文件数据
     * @param file_path 文件路径
     * @param offset 偏移量
     * @param length 读取长度
     * @return 是否发送成功
     */
    bool send_file_data(const std::string& file_path, uint64_t offset, uint64_t length);
    
    /**
     * @brief 发送单个数据块
     * @param data 数据
     * @param offset 偏移量
     * @param total_size 总大小
     * @param is_last_chunk 是否最后一块
     * @return 是否发送成功
     */
    bool send_data_chunk(const std::vector<uint8_t>& data, uint64_t offset, 
                         uint64_t total_size, bool is_last_chunk);
};

} // namespace server
} // namespace ft 