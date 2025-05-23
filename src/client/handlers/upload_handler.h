#pragma once

#include "../../common/protocol/messages/upload_message.h"
#include "../../common/network/socket/tcp_socket.h"
#include "../../common/utils/crypto/encryption.h"
#include <string>
#include <functional>
#include <memory>

namespace ft {
namespace client {

/**
 * @brief 上传处理程序类
 */
class UploadHandler {
public:
    /**
     * @brief 构造函数
     * @param local_file 本地文件路径
     * @param remote_file 远程文件路径
     * @param chunk_size 分块大小
     * @param progress_callback 进度回调函数
     * @param encryption_enabled 是否启用加密
     * @param encryption_key 加密密钥
     * @param encryption_iv 加密IV
     */
    UploadHandler(const std::string& local_file,
                 const std::string& remote_file,
                 size_t chunk_size,
                 std::function<void(size_t, size_t)> progress_callback = nullptr,
                 bool encryption_enabled = false,
                 const std::vector<uint8_t>& encryption_key = {},
                 const std::vector<uint8_t>& encryption_iv = {});
    
    /**
     * @brief 析构函数
     */
    ~UploadHandler();
    
    /**
     * @brief 执行上传
     * @param socket TCP套接字
     * @return 是否上传成功
     */
    bool upload(ft::network::TcpSocket& socket);
    
private:
    std::string local_file_;
    std::string remote_file_;
    size_t chunk_size_;
    std::function<void(size_t, size_t)> progress_callback_;
    bool encryption_enabled_;
    std::vector<uint8_t> encryption_key_;
    std::vector<uint8_t> encryption_iv_;
    
    /**
     * @brief 加密数据
     * @param data 要加密的数据
     * @return 加密后的数据
     */
    std::vector<uint8_t> encrypt_data(const std::vector<uint8_t>& data);
};

} // namespace client
} // namespace ft 