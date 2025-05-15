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

using namespace ft;
using namespace ft::protocol;
using namespace ft::network;

// 测试协议功能
void test_protocol() {
    std::cout << "=== Testing Protocol ===" << std::endl;
    
    // 测试上传消息
    UploadMessage upload_msg("test.txt", 0, 1024, false);
    std::string test_data = "Hello, World!";
    upload_msg.set_file_data(test_data.data(), test_data.size());
    
    std::vector<uint8_t> buffer;
    upload_msg.encode(buffer);
    
    // 使用正确的方式从缓冲区解码消息
    Message base_msg;
    base_msg.decode(buffer);
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
    
    // 测试下载消息
    DownloadMessage download_msg("test.txt", 0, 1024);
    buffer.clear();
    download_msg.encode(buffer);
    
    // 使用正确的方式从缓冲区解码消息
    base_msg = Message();
    base_msg.decode(buffer);
    DownloadMessage decoded_download_msg(base_msg);
    
    std::cout << "Download Message Test:" << std::endl;
    std::cout << "  Filename: " << decoded_download_msg.get_filename() << std::endl;
    std::cout << "  Offset: " << decoded_download_msg.get_offset() << std::endl;
    std::cout << "  Length: " << decoded_download_msg.get_length() << std::endl;
    std::cout << "  Is Request: " << (decoded_download_msg.is_request() ? "Yes" : "No") << std::endl;
    
    std::cout << std::endl;
}

// 测试网络功能
void test_network() {
    std::cout << "=== Testing Network ===" << std::endl;
    
    std::cout << "注意：此测试涉及网络通信，可能受到系统环境影响" << std::endl;
    
    // 创建套接字对象以测试基本功能
    try {
        // 测试服务器套接字创建
        TcpSocket server_socket;
        std::cout << "Server socket created successfully" << std::endl;
        
        // 测试客户端套接字创建
        TcpSocket client_socket;
        std::cout << "Client socket created successfully" << std::endl;
        
        // 测试基本属性
        std::cout << "Default socket options:" << std::endl;
        std::cout << "  Socket FD: " << server_socket.get_fd() << std::endl;
        std::cout << "  Is Connected: " << (server_socket.is_connected() ? "Yes" : "No") << std::endl;
        
        // 测试绑定功能（不实际监听）
        SocketError err = server_socket.bind("127.0.0.1", 0); // 使用系统分配的端口
        if (err == SocketError::SUCCESS) {
            std::cout << "Bind successful on: " 
                      << server_socket.get_local_address() << ":" 
                      << server_socket.get_local_port() << std::endl;
        } else {
            std::cout << "Bind failed with error: " << static_cast<int>(err) << std::endl;
        }
        
        std::cout << "网络功能基本测试完成" << std::endl;
        
    } catch (const std::exception& e) {
        std::cerr << "Network test exception: " << e.what() << std::endl;
    }
    
    std::cout << std::endl;
}

int main() {
    std::cout << "File Transfer Tool - Basic Test" << std::endl;
    std::cout << "===============================" << std::endl << std::endl;
    
    // 测试协议功能
    test_protocol();
    
    // 测试网络功能
    test_network();
    
    return 0;
} 