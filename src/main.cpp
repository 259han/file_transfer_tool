#include <iostream>
#include <string>
#include <vector>
#include <thread>
#include <chrono>
#include <memory>
#include <cstring>
#include <mutex>
#include <condition_variable>
#include "common/protocol/protocol.h"
#include "common/protocol/messages/upload_message.h"
#include "common/protocol/messages/download_message.h"
#include "common/network/socket/tcp_socket.h"
#include "common/utils/logging/logger.h"

using namespace ft;
using namespace ft::protocol;
using namespace ft::network;
using namespace ft::utils;

// 初始化日志系统
void init_logging() {
    // 初始化日志系统，设置为DEBUG级别
    Logger::instance().init(LogLevel::DEBUG, true, "test_log.txt");
    LOG_INFO("日志系统初始化完成");
}

// 测试协议功能
void test_protocol() {
    LOG_INFO("开始协议功能测试");
    std::cout << "=== Testing Protocol ===" << std::endl;
    
    // 测试上传消息
    UploadMessage upload_msg("test.txt", 0, 1024, false);
    std::string test_data = "Hello, World!";
    upload_msg.set_file_data(test_data.data(), test_data.size());
    
    std::vector<uint8_t> buffer;
    bool result = upload_msg.encode(buffer);
    if (!result) {
        LOG_ERROR("上传消息编码失败");
        std::cerr << "上传消息编码失败" << std::endl;
        return;
    }
    LOG_INFO("上传消息编码成功，缓冲区大小: %zu", buffer.size());
    
    // 使用正确的方式从缓冲区解码消息
    Message base_msg;
    result = base_msg.decode(buffer);
    if (!result) {
        LOG_ERROR("消息解码失败");
        std::cerr << "消息解码失败" << std::endl;
        return;
    }
    
    // 检查消息类型
    if (base_msg.get_operation_type() != OperationType::UPLOAD) {
        LOG_ERROR("消息类型错误: 期望 UPLOAD，实际 %d", static_cast<int>(base_msg.get_operation_type()));
        std::cerr << "消息类型错误" << std::endl;
        return;
    }
    
    UploadMessage decoded_msg(base_msg);
    
    std::cout << "Upload Message Test:" << std::endl;
    std::cout << "  Filename: " << decoded_msg.get_filename() << std::endl;
    std::cout << "  Offset: " << decoded_msg.get_offset() << std::endl;
    std::cout << "  Total Size: " << decoded_msg.get_total_size() << std::endl;
    std::cout << "  Is Last Chunk: " << (decoded_msg.is_last_chunk() ? "Yes" : "No") << std::endl;
    
    std::string decoded_data(
        reinterpret_cast<const char*>(decoded_msg.get_file_data().data()),
        decoded_msg.get_file_data().size()
    );
    std::cout << "  File Data: " << decoded_data << std::endl;
    
    LOG_INFO("上传消息测试成功");
    
    // 测试下载消息
    DownloadMessage download_msg("test.txt", 0, 1024);
    buffer.clear();
    result = download_msg.encode(buffer);
    if (!result) {
        LOG_ERROR("下载消息编码失败");
        std::cerr << "下载消息编码失败" << std::endl;
        return;
    }
    LOG_INFO("下载消息编码成功，缓冲区大小: %zu", buffer.size());
    
    // 使用正确的方式从缓冲区解码消息
    base_msg = Message();
    result = base_msg.decode(buffer);
    if (!result) {
        LOG_ERROR("消息解码失败");
        std::cerr << "消息解码失败" << std::endl;
        return;
    }
    
    // 检查消息类型
    if (base_msg.get_operation_type() != OperationType::DOWNLOAD) {
        LOG_ERROR("消息类型错误: 期望 DOWNLOAD，实际 %d", static_cast<int>(base_msg.get_operation_type()));
        std::cerr << "消息类型错误" << std::endl;
        return;
    }
    
    DownloadMessage decoded_download_msg(base_msg);
    
    std::cout << "Download Message Test:" << std::endl;
    std::cout << "  Filename: " << decoded_download_msg.get_filename() << std::endl;
    std::cout << "  Offset: " << decoded_download_msg.get_offset() << std::endl;
    std::cout << "  Length: " << decoded_download_msg.get_length() << std::endl;
    std::cout << "  Is Request: " << (decoded_download_msg.is_request() ? "Yes" : "No") << std::endl;
    
    LOG_INFO("下载消息测试成功");
    
    std::cout << std::endl;
}

// 测试网络功能
void test_network() {
    LOG_INFO("开始网络功能测试");
    std::cout << "=== Testing Network ===" << std::endl;
    
    std::cout << "注意：此测试涉及网络通信，可能受到系统环境影响" << std::endl;
    
    // 创建套接字对象以测试基本功能
    TcpSocket server_socket;
    if (server_socket.get_fd() < 0) {
        LOG_ERROR("服务器套接字创建失败: %d", static_cast<int>(server_socket.get_last_error()));
        std::cerr << "服务器套接字创建失败: " << static_cast<int>(server_socket.get_last_error()) << std::endl;
        return;
    }
    LOG_INFO("服务器套接字创建成功，fd=%d", server_socket.get_fd());
    std::cout << "Server socket created successfully" << std::endl;
    
    // 测试客户端套接字创建
    TcpSocket client_socket;
    if (client_socket.get_fd() < 0) {
        LOG_ERROR("客户端套接字创建失败: %d", static_cast<int>(client_socket.get_last_error()));
        std::cerr << "客户端套接字创建失败: " << static_cast<int>(client_socket.get_last_error()) << std::endl;
        return;
    }
    LOG_INFO("客户端套接字创建成功，fd=%d", client_socket.get_fd());
    std::cout << "Client socket created successfully" << std::endl;
    
    // 测试基本属性
    std::cout << "Default socket options:" << std::endl;
    std::cout << "  Socket FD: " << server_socket.get_fd() << std::endl;
    std::cout << "  Is Connected: " << (server_socket.is_connected() ? "Yes" : "No") << std::endl;
    
    // 测试绑定功能（不实际监听）
    SocketError err = server_socket.bind("127.0.0.1", 0); // 使用系统分配的端口
    if (err == SocketError::SUCCESS) {
        LOG_INFO("绑定成功: %s:%d", server_socket.get_local_address().c_str(), server_socket.get_local_port());
        std::cout << "Bind successful on: " 
                  << server_socket.get_local_address() << ":" 
                  << server_socket.get_local_port() << std::endl;
    } else {
        LOG_ERROR("绑定失败: %d", static_cast<int>(err));
        std::cout << "Bind failed with error: " << static_cast<int>(err) << std::endl;
    }
    
    LOG_INFO("网络功能测试完成");
    std::cout << "网络功能基本测试完成" << std::endl;
    
    std::cout << std::endl;
}

int main() {
    // 初始化日志系统
    init_logging();
    
    LOG_INFO("文件传输工具 - 基本测试开始");
    std::cout << "File Transfer Tool - Basic Test" << std::endl;
    std::cout << "===============================" << std::endl << std::endl;
    
    // 测试协议功能
    test_protocol();
    
    // 测试网络功能
    test_network();
    
    LOG_INFO("所有测试完成");
    return 0;
} 