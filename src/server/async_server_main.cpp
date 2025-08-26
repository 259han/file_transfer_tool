#include "core/async_server_core.h"
#include "../common/utils/logging/logger.h"
#include <iostream>
#include <signal.h>
#include <thread>
#include <chrono>

using namespace ft::server;

// 全局变量，用于信号处理
static bool g_server_running = true;

void signal_handler(int signal) {
    if (signal == SIGINT || signal == SIGTERM) {
        std::cout << "\nReceived signal " << signal << ", stopping async server..." << std::endl;
        g_server_running = false;
        AsyncServerCore::stop();
    }
}

void print_usage(const char* program_name) {
    std::cout << "Usage: " << program_name << " [config_file]" << std::endl;
    std::cout << "  config_file: Path to server configuration file (optional)" << std::endl;
}

int main(int argc, char* argv[]) {
    // 解析命令行参数
    std::string config_file;
    if (argc > 1) {
        if (std::string(argv[1]) == "--help" || std::string(argv[1]) == "-h") {
            print_usage(argv[0]);
            return 0;
        }
        config_file = argv[1];
    }
    
    // 设置信号处理
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);
    
    std::cout << "File Transfer Tool - Async Server v1.0" << std::endl;
    std::cout << "===========================================" << std::endl;
    
    try {
        // 初始化异步服务器
        if (!AsyncServerCore::init(config_file)) {
            LOG_ERROR("Failed to initialize async server");
            return 1;
        }
        
        std::cout << "Async server initialized successfully!" << std::endl;
        
        // 启动统计监控线程
        std::thread stats_thread([&]() {
            while (g_server_running) {
                std::this_thread::sleep_for(std::chrono::seconds(10));
                if (!g_server_running) break;
                
                auto stats = AsyncServerCore::get_statistics();
                LOG_INFO("=== Server Statistics ===");
                LOG_INFO("Active connections: %zu", stats.active_connections);
                LOG_INFO("Total connections: %zu", stats.total_connections);  
                LOG_INFO("Events per second: %zu", stats.events_per_second);
                LOG_INFO("Pending tasks: %zu", stats.pending_tasks);
                LOG_INFO("========================");
            }
        });
        
        // 运行异步服务器（阻塞）
        std::cout << "Starting async server..." << std::endl;
        AsyncServerCore::run();
        
        // 等待统计线程结束
        if (stats_thread.joinable()) {
            stats_thread.join();
        }
        
    } catch (const std::exception& e) {
        LOG_ERROR("Server exception: %s", e.what());
        std::cerr << "Server error: " << e.what() << std::endl;
        return 1;
    } catch (...) {
        LOG_ERROR("Unknown server exception");
        std::cerr << "Unknown server error" << std::endl;
        return 1;
    }
    
    std::cout << "Async server stopped." << std::endl;
    return 0;
}
