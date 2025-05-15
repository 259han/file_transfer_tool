#pragma once

#include "../../common/protocol/messages/download_message.h"
#include "../../common/network/socket/tcp_socket.h"
#include <string>
#include <functional>

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
     */
    DownloadHandler(const std::string& local_file,
                   const std::string& remote_file,
                   std::function<void(size_t, size_t)> progress_callback = nullptr);
    
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
};

} // namespace client
} // namespace ft 