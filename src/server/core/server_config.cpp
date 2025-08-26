#include "server_config.h"
#include "../../common/utils/logging/logger.h"
#include <fstream>
#include <sstream>
#include <iostream>
#include <filesystem>
#include <cstring>
#include <thread>

namespace fs = std::filesystem;

namespace ft {
namespace server {

ServerConfig::ServerConfig() {
    set_defaults();
}

ServerConfig& ServerConfig::instance() {
    static ServerConfig instance;
    return instance;
}

void ServerConfig::set_defaults() {
    // 基本配置
    listen_address_ = "0.0.0.0";
    listen_port_ = 8080;
    storage_path_ = "./storage";
    log_level_ = 2;  // INFO
    log_file_ = "./logs/server.log";
    max_connections_ = 1000;
    thread_pool_size_ = std::thread::hardware_concurrency();
    session_timeout_ = std::chrono::seconds(1800);  // 30分钟
    
    // 安全配置
    enable_encryption_ = false;
    tls_cert_file_ = "./certs/server.crt";
    tls_key_file_ = "./certs/server.key";
    users_file_ = "./config/users.json";
    
    // 版本控制配置
    enable_version_control_ = true;
    max_versions_per_file_ = 5;
    
    // TCP优化配置
    enable_tcp_optimization_ = true;
    tcp_send_buffer_size_ = 1024 * 1024;  // 1MB
    tcp_recv_buffer_size_ = 1024 * 1024;  // 1MB
    enable_tcp_nodelay_ = true;
    
    // 零拷贝传输配置
    enable_zero_copy_ = true;
    zero_copy_threshold_ = 64 * 1024;  // 64KB
}

bool ServerConfig::load_from_file(const std::string& config_file) {
    if (!fs::exists(config_file)) {
        LOG_ERROR("Configuration file not found: %s", config_file.c_str());
        return false;
    }
    
    return parse_config_file(config_file);
}

bool ServerConfig::load_from_args(int argc, char* argv[]) {
    return parse_command_line(argc, argv);
}

bool ServerConfig::parse_config_file(const std::string& config_file) {
    std::ifstream file(config_file);
    if (!file.is_open()) {
        LOG_ERROR("Failed to open configuration file: %s", config_file.c_str());
        return false;
    }
    
    std::string line;
    while (std::getline(file, line)) {
        // 跳过空行和注释
        if (line.empty() || line[0] == '#') {
            continue;
        }
        
        // 解析键值对
        size_t pos = line.find('=');
        if (pos == std::string::npos) {
            continue;
        }
        
        std::string key = line.substr(0, pos);
        std::string value = line.substr(pos + 1);
        
        // 去除前后空格
        key.erase(0, key.find_first_not_of(" \t"));
        key.erase(key.find_last_not_of(" \t") + 1);
        value.erase(0, value.find_first_not_of(" \t"));
        value.erase(value.find_last_not_of(" \t") + 1);
        
        // 解析配置项
        if (key == "listen_address") {
            listen_address_ = value;
        } else if (key == "listen_port") {
            listen_port_ = std::stoi(value);
        } else if (key == "storage_path") {
            storage_path_ = value;
        } else if (key == "log_level") {
            log_level_ = std::stoi(value);
        } else if (key == "log_file") {
            log_file_ = value;
        } else if (key == "max_connections") {
            max_connections_ = std::stoull(value);
        } else if (key == "thread_pool_size") {
            thread_pool_size_ = std::stoull(value);
        } else if (key == "session_timeout") {
            session_timeout_ = std::chrono::seconds(std::stoi(value));
        } else if (key == "enable_encryption") {
            enable_encryption_ = (value == "true" || value == "1");
        } else if (key == "tls_cert_file") {
            tls_cert_file_ = value;
        } else if (key == "tls_key_file") {
            tls_key_file_ = value;
        } else if (key == "users_file") {
            users_file_ = value;
        } else if (key == "enable_version_control") {
            enable_version_control_ = (value == "true" || value == "1");
        } else if (key == "max_versions_per_file") {
            max_versions_per_file_ = std::stoull(value);
        } else if (key == "enable_tcp_optimization") {
            enable_tcp_optimization_ = (value == "true" || value == "1");
        } else if (key == "tcp_send_buffer_size") {
            tcp_send_buffer_size_ = std::stoi(value);
        } else if (key == "tcp_recv_buffer_size") {
            tcp_recv_buffer_size_ = std::stoi(value);
        } else if (key == "enable_tcp_nodelay") {
            enable_tcp_nodelay_ = (value == "true" || value == "1");
        } else if (key == "enable_zero_copy") {
            enable_zero_copy_ = (value == "true" || value == "1");
        } else if (key == "zero_copy_threshold") {
            zero_copy_threshold_ = std::stoull(value);
        } else {
            LOG_WARNING("Unknown configuration key: %s", key.c_str());
        }
    }
    
    LOG_INFO("Configuration loaded from file: %s", config_file.c_str());
    LOG_INFO("TCP optimization: %s, Zero-copy: %s", 
             enable_tcp_optimization_ ? "enabled" : "disabled",
             enable_zero_copy_ ? "enabled" : "disabled");
    
    return true;
}

bool ServerConfig::parse_command_line(int argc, char* argv[]) {
    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];
        
        if (arg == "--help" || arg == "-h") {
            std::cout << "Usage: " << argv[0] << " [options]\n"
                      << "Options:\n"
                      << "  -h, --help                 Show this help message\n"
                      << "  -c, --config <file>        Load configuration from file\n"
                      << "  -a, --address <address>    Set listen address\n"
                      << "  -p, --port <port>          Set listen port\n"
                      << "  -s, --storage <path>       Set storage path\n"
                      << "  -l, --log-level <level>    Set log level (0-4)\n"
                      << "  -f, --log-file <file>      Set log file\n"
                      << "  -t, --threads <count>      Set thread pool size\n"
                      << "  --enable-encryption        Enable encryption\n"
                      << "  --disable-encryption       Disable encryption\n"
                      << "  --enable-version-control   Enable version control\n"
                      << "  --disable-version-control  Disable version control\n"
                      << "  --enable-tcp-optimization  Enable TCP optimization\n"
                      << "  --disable-tcp-optimization Disable TCP optimization\n"
                      << "  --enable-zero-copy         Enable zero-copy transfer\n"
                      << "  --disable-zero-copy        Disable zero-copy transfer\n"
                      << std::endl;
            return false;
        } else if (arg == "--config" || arg == "-c") {
            if (i + 1 < argc) {
                return load_from_file(argv[++i]);
            } else {
                std::cerr << "Missing configuration file path\n";
                return false;
            }
        } else if (arg == "--address" || arg == "-a") {
            if (i + 1 < argc) {
                listen_address_ = argv[++i];
            } else {
                std::cerr << "Missing listen address\n";
                return false;
            }
        } else if (arg == "--port" || arg == "-p") {
            if (i + 1 < argc) {
                listen_port_ = std::stoi(argv[++i]);
            } else {
                std::cerr << "Missing listen port\n";
                return false;
            }
        } else if (arg == "--storage" || arg == "-s") {
            if (i + 1 < argc) {
                storage_path_ = argv[++i];
            } else {
                std::cerr << "Missing storage path\n";
                return false;
            }
        } else if (arg == "--log-level" || arg == "-l") {
            if (i + 1 < argc) {
                log_level_ = std::stoi(argv[++i]);
            } else {
                std::cerr << "Missing log level\n";
                return false;
            }
        } else if (arg == "--log-file" || arg == "-f") {
            if (i + 1 < argc) {
                log_file_ = argv[++i];
            } else {
                std::cerr << "Missing log file\n";
                return false;
            }
        } else if (arg == "--threads" || arg == "-t") {
            if (i + 1 < argc) {
                thread_pool_size_ = std::stoull(argv[++i]);
            } else {
                std::cerr << "Missing thread count\n";
                return false;
            }
        } else if (arg == "--enable-encryption") {
            enable_encryption_ = true;
        } else if (arg == "--disable-encryption") {
            enable_encryption_ = false;
        } else if (arg == "--enable-version-control") {
            enable_version_control_ = true;
        } else if (arg == "--disable-version-control") {
            enable_version_control_ = false;
        } else if (arg == "--enable-tcp-optimization") {
            enable_tcp_optimization_ = true;
        } else if (arg == "--disable-tcp-optimization") {
            enable_tcp_optimization_ = false;
        } else if (arg == "--enable-zero-copy") {
            enable_zero_copy_ = true;
        } else if (arg == "--disable-zero-copy") {
            enable_zero_copy_ = false;
        } else {
            std::cerr << "Unknown option: " << arg << "\n";
            return false;
        }
    }
    
    LOG_INFO("Configuration loaded from command line");
    LOG_INFO("TCP optimization: %s, Zero-copy: %s", 
             enable_tcp_optimization_ ? "enabled" : "disabled",
             enable_zero_copy_ ? "enabled" : "disabled");
    
    return true;
}

} // namespace server
} // namespace ft
