#pragma once

#include "../../common/protocol/messages/upload_message.h"
#include "../../common/network/socket/tcp_socket.h"
#include <string>
#include <functional>

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
     */
    UploadHandler(const std::string& local_file,
                 const std::string& remote_file,
                 size_t chunk_size,
                 std::function<void(size_t, size_t)> progress_callback = nullptr);
    
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
};

} // namespace client
} // namespace ft 