#include <gtest/gtest.h>
#include "../../src/common/utils/crypto/encryption.h"
#include "../../src/common/protocol/messages/key_exchange_message.h"
#include "../../src/client/core/client_core.h"
#include <iostream>
#include <fstream>
#include <filesystem>
#include <string>
#include <vector>
#include <chrono>
#include <thread>
#include <algorithm>
#include <cstring>
namespace fs = std::filesystem;

using namespace ft;
using namespace client;

// 创建测试文件
bool create_test_file(const std::string& path, size_t size) {
    try {
        // 确保目录存在
        fs::path file_path(path);
        if (!file_path.parent_path().empty()) {
            fs::create_directories(file_path.parent_path());
        }
        
        // 创建并填充文件
        std::ofstream file(path, std::ios::binary);
        if (!file) {
            std::cerr << "无法创建测试文件: " << path << std::endl;
            return false;
        }
        
        // 生成随机数据
        std::vector<char> buffer(std::min(size, size_t(1024 * 1024))); // 最大1MB缓冲区
        
        // 写入文件
        size_t remaining = size;
        while (remaining > 0) {
            size_t block_size = std::min(remaining, buffer.size());
            // 生成随机内容
            std::generate(buffer.begin(), buffer.begin() + block_size, []() { return rand() % 256; });
            
            file.write(buffer.data(), block_size);
            remaining -= block_size;
        }
        
        file.close();
        return true;
    } catch (const std::exception& e) {
        std::cerr << "创建测试文件异常: " << e.what() << std::endl;
        return false;
    }
}

// 比较两个文件内容是否一致
bool compare_files(const std::string& file1, const std::string& file2) {
    try {
        // 检查文件是否存在
        if (!fs::exists(file1) || !fs::exists(file2)) {
            std::cerr << "文件不存在，无法比较" << std::endl;
            return false;
        }
        
        // 检查文件大小是否相同
        if (fs::file_size(file1) != fs::file_size(file2)) {
            std::cerr << "文件大小不同: " 
                   << file1 << " (" << fs::file_size(file1) << " bytes), "
                   << file2 << " (" << fs::file_size(file2) << " bytes)" << std::endl;
            return false;
        }
        
        // 逐块比较文件内容
        std::ifstream f1(file1, std::ios::binary);
        std::ifstream f2(file2, std::ios::binary);
        
        if (!f1 || !f2) {
            std::cerr << "无法打开文件进行比较" << std::endl;
            return false;
        }
        
        constexpr size_t BUFFER_SIZE = 4096;
        char buffer1[BUFFER_SIZE];
        char buffer2[BUFFER_SIZE];
        
        while (f1 && f2) {
            f1.read(buffer1, BUFFER_SIZE);
            f2.read(buffer2, BUFFER_SIZE);
            
            std::streamsize count1 = f1.gcount();
            std::streamsize count2 = f2.gcount();
            
            if (count1 != count2 || std::memcmp(buffer1, buffer2, count1) != 0) {
                return false;
            }
            
            if (static_cast<size_t>(count1) < BUFFER_SIZE) break; // 文件结束
        }
        
        return true;
    } catch (const std::exception& e) {
        std::cerr << "比较文件异常: " << e.what() << std::endl;
        return false;
    }
}

class EncryptionE2ETest : public ::testing::Test {
protected:
    void SetUp() override {
        // 初始化随机数生成器
        std::srand(static_cast<unsigned int>(std::time(nullptr)));
        
        // 初始化客户端
        client_.initialize(utils::LogLevel::INFO);
        
        // 创建测试目录
        test_dir_ = "encryption_test";
        if (fs::exists(test_dir_)) {
            fs::remove_all(test_dir_);
        }
        fs::create_directories(test_dir_);
    }
    
    void TearDown() override {
        // 断开连接
        if (client_.is_connected()) {
            client_.disconnect();
        }
        
        // 不清理测试目录，保留测试文件供分析
        std::cout << "保留测试目录文件供分析: " << test_dir_ << std::endl;
        // if (fs::exists(test_dir_)) {
        //     fs::remove_all(test_dir_);
        // }
    }
    
    ClientCore client_;
    std::string test_dir_;
};

// 测试不同大小文件的加密传输
TEST_F(EncryptionE2ETest, FileTransferWithEncryption) {
    // 测试参数设置
    std::vector<size_t> test_sizes = {
        1024 * 10,      // 10KB
        1024 * 100,     // 100KB
        1024 * 1024     // 1MB
    };
    
    // 连接到服务器
    ServerInfo server_info;
    server_info.host = "localhost";
    server_info.port = 9899;
    
    ASSERT_TRUE(client_.connect(server_info)) << "无法连接到服务器";
    
    // 一次完整测试所有非加密模式
    client_.disable_encryption();
    for (size_t file_size : test_sizes) {
        // 测试文件路径
        std::string upload_file = test_dir_ + "/upload_" + std::to_string(file_size) + ".dat";
        std::string remote_file = "upload_" + std::to_string(file_size) + ".dat";
        std::string download_file = test_dir_ + "/download_" + std::to_string(file_size) + ".dat";
        
        // 创建测试文件
        ASSERT_TRUE(create_test_file(upload_file, file_size)) << "创建测试文件失败";
        
        // 上传测试
        TransferRequest upload_request;
        upload_request.local_file = upload_file;
        upload_request.remote_file = remote_file;
        
        TransferResult upload_result = client_.upload(upload_request);
        ASSERT_TRUE(upload_result.success) << "上传失败: " << upload_result.error_message;
        
        // 下载测试
        TransferRequest download_request;
        download_request.remote_file = remote_file;
        download_request.local_file = download_file;
        
        TransferResult download_result = client_.download(download_request);
        ASSERT_TRUE(download_result.success) << "下载失败: " << download_result.error_message;
        
        // 验证文件内容
        ASSERT_TRUE(compare_files(upload_file, download_file)) << "文件验证失败";
    }
    
    // 然后测试所有加密模式
    ASSERT_TRUE(client_.enable_encryption()) << "启用加密失败";
    
    for (size_t file_size : test_sizes) {
        // 测试文件路径
        std::string upload_file = test_dir_ + "/upload_" + std::to_string(file_size) + ".dat";
        std::string remote_file = "upload_encrypted_" + std::to_string(file_size) + ".dat";
        std::string download_file = test_dir_ + "/download_encrypted_" + std::to_string(file_size) + ".dat";
        
        // 上传测试
        TransferRequest upload_request;
        upload_request.local_file = upload_file;
        upload_request.remote_file = remote_file;
        
        TransferResult upload_result = client_.upload(upload_request);
        ASSERT_TRUE(upload_result.success) << "加密上传失败: " << upload_result.error_message;
        
        // 下载测试
        TransferRequest download_request;
        download_request.remote_file = remote_file;
        download_request.local_file = download_file;
        
        TransferResult download_result = client_.download(download_request);
        ASSERT_TRUE(download_result.success) << "加密下载失败: " << download_result.error_message;
        
        // 验证文件内容
        ASSERT_TRUE(compare_files(upload_file, download_file)) << "加密传输文件验证失败";
    }
} 