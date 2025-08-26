#include "core/server_core.h"
#include "../common/utils/logging/logger.h"
#include "../common/utils/config/config_manager.h"
#include <iostream>
#include <string>
#include <csignal>
#include <thread>

using namespace ft;
using namespace ft::server;

// 全局服务器对象
static ft::server::ServerCore g_server;

// 信号处理函数
void signal_handler(int sig) {
    LOG_INFO("接收到信号: %d", sig);
    g_server.stop();
}

// 显示帮助信息
void show_help() {
    std::cout << "文件传输服务器 v1.0" << std::endl;
    std::cout << "用法:" << std::endl;
    std::cout << "  server [选项]" << std::endl;
    std::cout << "选项:" << std::endl;
    std::cout << "  -h, --help            显示帮助信息" << std::endl;
    std::cout << "  -p, --port <端口>     指定监听端口 (默认: 12345)" << std::endl;
    std::cout << "  -d, --dir <目录>      指定存储目录 (默认: ./storage)" << std::endl;
    std::cout << "  -c, --config <文件>   指定配置文件" << std::endl;
    std::cout << "  -v, --verbose         启用详细日志" << std::endl;
    std::cout << "  --log-level <级别>    设置日志级别 (debug, info, warning, error) (默认: info)" << std::endl;
}

// 解析命令行参数
void parse_args(int argc, char* argv[]) {
    ServerConfig& config = ServerConfig::instance();
    
    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];
        
        if (arg == "-h" || arg == "--help") {
            show_help();
            exit(0);
        } else if (arg == "-p" || arg == "--port") {
            if (i + 1 < argc) {
                config.set_listen_port(static_cast<uint16_t>(std::stoi(argv[++i])));
            }
        } else if (arg == "-d" || arg == "--dir") {
            if (i + 1 < argc) {
                config.set_storage_path(argv[++i]);
            }
        } else if (arg == "-c" || arg == "--config") {
            if (i + 1 < argc) {
                // 加载配置文件
                config.load_from_file(argv[++i]);
            }
        } else if (arg == "-v" || arg == "--verbose") {
            // 在初始化时会设置详细日志
            config.set_log_level(0); // debug level
        } else if (arg == "--log-level") {
            // 在初始化时会设置日志级别
        }
    }
}

int main(int argc, char* argv[]) {
    // 注册信号处理
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);
    
    // 解析命令行参数
    parse_args(argc, argv);
    ServerConfig& config = ServerConfig::instance();
    
    // 检查日志级别参数
    utils::LogLevel log_level = utils::LogLevel::INFO;
    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];
        if (arg == "-v" || arg == "--verbose") {
            log_level = utils::LogLevel::DEBUG;
        } else if (arg == "--log-level" && i + 1 < argc) {
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
        }
    }
    
    // 初始化服务器
    if (!g_server.initialize(config, log_level)) {
        std::cerr << "服务器初始化失败" << std::endl;
        return 1;
    }
    
    // 启动服务器
    if (!g_server.start()) {
        std::cerr << "服务器启动失败" << std::endl;
        return 1;
    }
    
    std::cout << "服务器已启动，监听端口: " << config.get_listen_port() << std::endl;
    std::cout << "使用 Ctrl+C 停止服务器" << std::endl;
    
    // 等待服务器停止
    g_server.wait();
    
    std::cout << "服务器已停止" << std::endl;
    
    return 0;
} 