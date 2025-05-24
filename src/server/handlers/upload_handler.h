#pragma once

#include "protocol_handler.h"

namespace ft {
namespace protocol {
    class UploadMessage; // 前向声明
}

namespace server {

/**
 * @brief 上传处理器
 * 负责处理客户端的文件上传请求
 */
class UploadHandler : public ProtocolHandler {
public:
    /**
     * @brief 构造函数
     * @param session 客户端会话引用
     */
    explicit UploadHandler(ClientSession& session);
    
    /**
     * @brief 析构函数
     */
    ~UploadHandler() override = default;
    
    /**
     * @brief 处理上传消息
     * @param buffer 消息缓冲区
     * @return 是否处理成功
     */
    bool handle(const std::vector<uint8_t>& buffer) override;

private:
    /**
     * @brief 处理单个上传块
     * @param upload_msg 上传消息
     * @return 是否处理成功
     */
    bool process_upload_chunk(const protocol::UploadMessage& upload_msg);
    
    /**
     * @brief 发送上传响应
     * @param is_last_chunk 是否是最后一个块
     * @return 是否发送成功
     */
    bool send_upload_response(bool is_last_chunk);
};

} // namespace server
} // namespace ft 