#pragma once

#include "../../common/protocol/messages/download_message.h"
#include "../../common/network/socket/tcp_socket.h"
#include "../../common/utils/crypto/encryption.h"
#include <string>
#include <functional>
#include <memory>

namespace ft {
namespace client {

/**
 * @brief 下载处理程序类
 */
class DownloadHandler {
public:
    /**
     * @brief 构造函数
     * @param local_file 本地文件路径
     * @param remote_file 远程文件路径
     * @param progress_callback 进度回调函数
     * @param encryption_enabled 是否启用加密
     * @param encryption_key 加密密钥
     * @param encryption_iv 加密IV
     */
    DownloadHandler(const std::string& local_file,
                   const std::string& remote_file,
                   std::function<void(size_t, size_t)> progress_callback = nullptr,
                   bool encryption_enabled = false,
                   const std::vector<uint8_t>& encryption_key = {},
                   const std::vector<uint8_t>& encryption_iv = {});
    
    /**
     * @brief 析构函数
     */
    ~DownloadHandler();
    
    /**
     * @brief 执行下载
     * @param socket TCP套接字
     * @return 是否下载成功
     */
    bool download(ft::network::TcpSocket& socket);
    
private:
    std::string local_file_;
    std::string remote_file_;
    std::function<void(size_t, size_t)> progress_callback_;
    bool encryption_enabled_;
    std::vector<uint8_t> encryption_key_;
    std::vector<uint8_t> encryption_iv_;
    
    /**
     * @brief 解密数据
     * @param data 要解密的数据
     * @return 解密后的数据
     */
    std::vector<uint8_t> decrypt_data(const std::vector<uint8_t>& data);
};

} // namespace client
} // namespace ft 