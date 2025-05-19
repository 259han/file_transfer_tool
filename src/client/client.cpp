#include "core/client_core.h"
#include "../common/protocol/protocol.h"
#include "../common/protocol/messages/upload_message.h"
#include "../common/protocol/messages/download_message.h"
#include <iostream>
#include <string>
#include <iomanip>
#include <thread>
#include <mutex>
#include <condition_variable>
#include <cstring>

using namespace ft;
using namespace ft::client;
using namespace ft::utils;

// 进度显示
class ProgressBar {
public:
    ProgressBar(size_t total = 0, size_t width = 50) 
        : total_(total), width_(width), progress_(0), finished_(false) {
    }
    
    // 禁用复制构造函数
    ProgressBar(const ProgressBar&) = delete;
    // 禁用复制赋值运算符
    ProgressBar& operator=(const ProgressBar&) = delete;
    
    // 移动构造函数
    ProgressBar(ProgressBar&& other) noexcept
        : total_(other.total_),
          width_(other.width_),
          progress_(other.progress_),
          finished_(other.finished_) {
        // 不需要移动 mutex 和 condition_variable
    }
    
    // 移动赋值运算符
    ProgressBar& operator=(ProgressBar&& other) noexcept {
        if (this != &other) {
            total_ = other.total_;
            width_ = other.width_;
            progress_ = other.progress_;
            finished_ = other.finished_;
            // 不需要移动 mutex 和 condition_variable
        }
        return *this;
    }
    
    // 重置进度条
    void reset(size_t total) {
        std::lock_guard<std::mutex> lock(mutex_);
        total_ = total;
        progress_ = 0;
        finished_ = false;
    }
    
    void update(size_t progress) {
        std::lock_guard<std::mutex> lock(mutex_);
        progress_ = progress;
        if (progress_ >= total_) {
            finished_ = true;
            cv_.notify_all();
        }
    }
    
    void start() {
        std::thread([this]() {
            std::unique_lock<std::mutex> lock(mutex_);
            while (!finished_) {
                display();
                cv_.wait_for(lock, std::chrono::milliseconds(100));
            }
            display();
            std::cout << std::endl;
        }).detach();
    }
    
private:
    void display() {
        double percentage = static_cast<double>(progress_) / total_;
        size_t pos = static_cast<size_t>(width_ * percentage);
        
        std::cout << "\r[";
        for (size_t i = 0; i < width_; ++i) {
            if (i < pos) std::cout << "=";
            else if (i == pos) std::cout << ">";
            else std::cout << " ";
        }
        
        std::cout << "] " << static_cast<int>(percentage * 100.0) << "% "
                 << progress_ << "/" << total_ << " bytes";
        std::cout.flush();
    }
    
private:
    size_t total_;
    size_t width_;
    size_t progress_;
    bool finished_;
    std::mutex mutex_;
    std::condition_variable cv_;
};

// 显示帮助信息
void show_help() {
    std::cout << "文件传输客户端使用方法:" << std::endl;
    std::cout << "  upload <server> <port> <local_file> [remote_file]" << std::endl;
    std::cout << "    上传文件到服务器" << std::endl;
    std::cout << "  download <server> <port> <remote_file> [local_file]" << std::endl;
    std::cout << "    从服务器下载文件" << std::endl;
    std::cout << "  test <server> <port>" << std::endl;
    std::cout << "    测试与服务器的连接" << std::endl;
    std::cout << "其他选项:" << std::endl;
    std::cout << "  --log-level <level>  设置日志级别 (debug, info, warning, error)" << std::endl;
    std::cout << "  --no-encrypt         禁用加密传输（默认启用加密）" << std::endl;
}

// 上传文件
void upload_file(const std::string& server, uint16_t port, const std::string& local_file, 
                const std::string& remote_file, utils::LogLevel log_level, bool use_encryption) {
    // 创建客户端
    ClientCore client;
    client.initialize(log_level);
    
    // 连接服务器
    ServerInfo server_info;
    server_info.host = server;
    server_info.port = port;
    
    std::cout << "连接到服务器 " << server << ":" << port << "..." << std::endl;
    if (!client.connect(server_info)) {
        std::cerr << "连接服务器失败!" << std::endl;
        return;
    }
    
    // 启用加密（如果需要）
    if (use_encryption) {
        std::cout << "启用加密传输..." << std::endl;
        if (!client.enable_encryption()) {
            std::cerr << "警告: 无法启用加密，将使用非加密传输" << std::endl;
        } else {
            std::cout << "加密已启用" << std::endl;
        }
    }
    
    // 创建进度条
    ProgressBar progress_bar;
    client.set_progress_callback([&progress_bar](size_t current, size_t total) {
        static bool initialized = false;
        if (!initialized) {
            progress_bar.reset(total);
            progress_bar.start();
            initialized = true;
        }
        progress_bar.update(current);
    });
    
    // 执行上传
    TransferRequest request;
    request.local_file = local_file;
    request.remote_file = remote_file;
    
    std::cout << "上传文件 " << local_file << " 到 " << remote_file << "..." << std::endl;
    TransferResult result = client.upload(request);
    
    // 显示结果
    if (result.success) {
        std::cout << "上传成功!" << std::endl;
        std::cout << "  传输大小: " << result.transferred_bytes << " 字节" << std::endl;
        std::cout << "  耗时: " << std::fixed << std::setprecision(2) << result.elapsed_seconds << " 秒" << std::endl;
        std::cout << "  速度: " << std::fixed << std::setprecision(2) 
                 << (result.transferred_bytes / 1024.0 / 1024.0) / result.elapsed_seconds << " MB/s" << std::endl;
        std::cout << "  加密: " << (use_encryption ? "是" : "否") << std::endl;
    } else {
        std::cerr << "上传失败: " << result.error_message << std::endl;
    }
}

// 下载文件
void download_file(const std::string& server, uint16_t port, const std::string& remote_file, 
                  const std::string& local_file, utils::LogLevel log_level, bool use_encryption) {
    // 创建客户端
    ClientCore client;
    client.initialize(log_level);
    
    // 连接服务器
    ServerInfo server_info;
    server_info.host = server;
    server_info.port = port;
    
    std::cout << "连接到服务器 " << server << ":" << port << "..." << std::endl;
    if (!client.connect(server_info)) {
        std::cerr << "连接服务器失败!" << std::endl;
        return;
    }
    
    // 启用加密（如果需要）
    if (use_encryption) {
        std::cout << "启用加密传输..." << std::endl;
        if (!client.enable_encryption()) {
            std::cerr << "警告: 无法启用加密，将使用非加密传输" << std::endl;
        } else {
            std::cout << "加密已启用" << std::endl;
        }
    }
    
    // 创建进度条
    ProgressBar progress_bar;
    client.set_progress_callback([&progress_bar](size_t current, size_t total) {
        static bool initialized = false;
        if (!initialized && total > 0) {
            progress_bar.reset(total);
            progress_bar.start();
            initialized = true;
        }
        progress_bar.update(current);
    });
    
    // 执行下载
    TransferRequest request;
    request.remote_file = remote_file;
    request.local_file = local_file;
    
    std::cout << "下载文件 " << remote_file << " 到 " << local_file << "..." << std::endl;
    TransferResult result = client.download(request);
    
    // 显示结果
    if (result.success) {
        std::cout << "下载成功!" << std::endl;
        std::cout << "  传输大小: " << result.transferred_bytes << " 字节" << std::endl;
        std::cout << "  耗时: " << std::fixed << std::setprecision(2) << result.elapsed_seconds << " 秒" << std::endl;
        std::cout << "  速度: " << std::fixed << std::setprecision(2) 
                 << (result.transferred_bytes / 1024.0 / 1024.0) / result.elapsed_seconds << " MB/s" << std::endl;
        std::cout << "  加密: " << (use_encryption ? "是" : "否") << std::endl;
    } else {
        std::cerr << "下载失败: " << result.error_message << std::endl;
    }
}

// 测试连接
void test_connection(const std::string& server, uint16_t port, utils::LogLevel log_level, bool use_encryption) {
    std::cout << "测试与服务器 " << server << ":" << port << " 的连接..." << std::endl;
    
    // 创建客户端
    ClientCore client;
    client.initialize(log_level);
    
    // 连接服务器
    ServerInfo server_info;
    server_info.host = server;
    server_info.port = port;
    
    // 记录开始时间
    auto start_time = std::chrono::high_resolution_clock::now();
    
    // 尝试连接
    std::cout << "尝试建立连接..." << std::endl;
    if (!client.connect(server_info)) {
        std::cerr << "连接失败: 无法连接到服务器" << std::endl;
        return;
    }
    
    // 如果需要，启用加密
    bool encryption_success = false;
    if (use_encryption) {
        std::cout << "测试加密..." << std::endl;
        encryption_success = client.enable_encryption();
        if (!encryption_success) {
            std::cerr << "警告: 无法启用加密" << std::endl;
        }
    }
    
    // 测试心跳
    std::cout << "连接成功，测试心跳..." << std::endl;
    if (!client.send_heartbeat()) {
        std::cerr << "心跳测试失败: 服务器没有响应心跳请求" << std::endl;
        client.disconnect();
        return;
    }
    
    // 测试连接状态
    std::cout << "心跳测试成功，验证连接状态..." << std::endl;
    if (!client.is_connected()) {
        std::cerr << "连接测试失败: 连接状态异常" << std::endl;
        client.disconnect();
        return;
    }
    
    // 计算连接耗时
    auto end_time = std::chrono::high_resolution_clock::now();
    double elapsed_seconds = std::chrono::duration<double>(end_time - start_time).count();
    
    // 显示成功结果
    std::cout << "连接测试成功!" << std::endl;
    std::cout << "  服务器: " << server << ":" << port << std::endl;
    std::cout << "  连接耗时: " << std::fixed << std::setprecision(3) << elapsed_seconds << " 秒" << std::endl;
    std::cout << "  心跳: 正常" << std::endl;
    std::cout << "  连接状态: 已连接" << std::endl;
    std::cout << "  加密: " << (encryption_success ? "已启用" : "未启用") << std::endl;
    
    // 断开连接
    client.disconnect();
    std::cout << "连接已关闭" << std::endl;
}

int main(int argc, char* argv[]) {
    if (argc < 2) {
        show_help();
        return 1;
    }
    
    std::string command = argv[1];
    
    // 处理帮助命令
    if (command == "help" || command == "--help" || command == "-h") {
        show_help();
        return 0;
    }
    
    // 设置日志级别和加密选项（默认启用加密）
    utils::LogLevel log_level = utils::LogLevel::INFO;
    bool use_encryption = true;  // 默认启用加密
    
    for (int i = 2; i < argc; ++i) {
        std::string arg = argv[i];
        if (arg == "--log-level" && i + 1 < argc) {
            std::string level = argv[++i];
            if (level == "debug") {
                log_level = utils::LogLevel::DEBUG;
            } else if (level == "info") {
                log_level = utils::LogLevel::INFO;
            } else if (level == "warning") {
                log_level = utils::LogLevel::WARNING;
            } else if (level == "error") {
                log_level = utils::LogLevel::ERROR;
            }
        } else if (arg == "--no-encrypt") {
            use_encryption = false;  // 禁用加密
        }
    }
    
    // 根据命令执行相应操作
    if (command == "upload") {
        // 检查参数数量
        if (argc < 5) {
            std::cerr << "参数不足: upload <server> <port> <local_file> [remote_file]" << std::endl;
            return 1;
        }
        
        // 解析参数
        std::string server = argv[2];
        uint16_t port = static_cast<uint16_t>(std::stoi(argv[3]));
        std::string local_file = argv[4];
        std::string remote_file = (argc > 5) ? argv[5] : local_file;
        
        // 执行上传
        upload_file(server, port, local_file, remote_file, log_level, use_encryption);
        
    } else if (command == "download") {
        // 检查参数数量
        if (argc < 5) {
            std::cerr << "参数不足: download <server> <port> <remote_file> [local_file]" << std::endl;
            return 1;
        }
        
        // 解析参数
        std::string server = argv[2];
        uint16_t port = static_cast<uint16_t>(std::stoi(argv[3]));
        std::string remote_file = argv[4];
        std::string local_file = (argc > 5) ? argv[5] : remote_file;
        
        // 执行下载
        download_file(server, port, remote_file, local_file, log_level, use_encryption);
        
    } else if (command == "test") {
        // 检查参数数量
        if (argc < 4) {
            std::cerr << "参数不足: test <server> <port>" << std::endl;
            return 1;
        }
        
        // 解析参数
        std::string server = argv[2];
        uint16_t port = static_cast<uint16_t>(std::stoi(argv[3]));
        
        // 执行连接测试
        test_connection(server, port, log_level, use_encryption);
        
    } else {
        std::cerr << "未知命令: " << command << std::endl;
        show_help();
        return 1;
    }
    
    return 0;
} 