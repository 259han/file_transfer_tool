#pragma once

#include <string>
#include <vector>
#include <memory>
#include <chrono>
#include <unordered_map>

namespace ft {
namespace server {

// 服务器配置类
class ServerConfig {
public:
    // 获取单例实例
    static ServerConfig& instance();
    
    // 从配置文件加载配置
    bool load_from_file(const std::string& config_file);
    
    // 从命令行参数加载配置
    bool load_from_args(int argc, char* argv[]);
    
    // 获取监听地址
    const std::string& get_listen_address() const { return listen_address_; }
    
    // 获取监听端口
    uint16_t get_listen_port() const { return listen_port_; }
    
    // 获取存储路径
    const std::string& get_storage_path() const { return storage_path_; }
    
    // 获取日志级别
    int get_log_level() const { return log_level_; }
    
    // 获取日志文件路径
    const std::string& get_log_file() const { return log_file_; }
    
    // 获取最大连接数
    size_t get_max_connections() const { return max_connections_; }
    
    // 获取线程池大小
    size_t get_thread_pool_size() const { return thread_pool_size_; }
    
    // 获取会话超时时间
    std::chrono::seconds get_session_timeout() const { return session_timeout_; }
    
    // 获取是否启用加密
    bool is_encryption_enabled() const { return enable_encryption_; }
    
    // 获取TLS证书路径
    const std::string& get_tls_cert_file() const { return tls_cert_file_; }
    
    // 获取TLS密钥路径
    const std::string& get_tls_key_file() const { return tls_key_file_; }
    
    // 获取用户配置文件路径
    const std::string& get_users_file() const { return users_file_; }
    
    // 获取版本控制配置
    bool is_version_control_enabled() const { return enable_version_control_; }
    size_t get_max_versions_per_file() const { return max_versions_per_file_; }
    
    // 获取TCP优化配置
    bool is_tcp_optimization_enabled() const { return enable_tcp_optimization_; }
    int get_tcp_send_buffer_size() const { return tcp_send_buffer_size_; }
    int get_tcp_recv_buffer_size() const { return tcp_recv_buffer_size_; }
    bool is_tcp_nodelay_enabled() const { return enable_tcp_nodelay_; }
    
    // 获取零拷贝传输配置
    bool is_zero_copy_enabled() const { return enable_zero_copy_; }
    size_t get_zero_copy_threshold() const { return zero_copy_threshold_; }
    
    // 设置监听地址
    void set_listen_address(const std::string& address) { listen_address_ = address; }
    
    // 设置监听端口
    void set_listen_port(uint16_t port) { listen_port_ = port; }
    
    // 设置存储路径
    void set_storage_path(const std::string& path) { storage_path_ = path; }
    
    // 设置日志级别
    void set_log_level(int level) { log_level_ = level; }
    
    // 设置日志文件路径
    void set_log_file(const std::string& file) { log_file_ = file; }
    
    // 设置最大连接数
    void set_max_connections(size_t max_conn) { max_connections_ = max_conn; }
    
    // 设置线程池大小
    void set_thread_pool_size(size_t size) { thread_pool_size_ = size; }
    
    // 设置会话超时时间
    void set_session_timeout(std::chrono::seconds timeout) { session_timeout_ = timeout; }
    
    // 设置是否启用加密
    void set_encryption_enabled(bool enabled) { enable_encryption_ = enabled; }
    
    // 设置TLS证书路径
    void set_tls_cert_file(const std::string& file) { tls_cert_file_ = file; }
    
    // 设置TLS密钥路径
    void set_tls_key_file(const std::string& file) { tls_key_file_ = file; }
    
    // 设置用户配置文件路径
    void set_users_file(const std::string& file) { users_file_ = file; }
    
    // 设置版本控制配置
    void set_version_control_enabled(bool enabled) { enable_version_control_ = enabled; }
    void set_max_versions_per_file(size_t max_versions) { max_versions_per_file_ = max_versions; }
    
    // 设置TCP优化配置
    void set_tcp_optimization_enabled(bool enabled) { enable_tcp_optimization_ = enabled; }
    void set_tcp_send_buffer_size(int size) { tcp_send_buffer_size_ = size; }
    void set_tcp_recv_buffer_size(int size) { tcp_recv_buffer_size_ = size; }
    void set_tcp_nodelay_enabled(bool enabled) { enable_tcp_nodelay_ = enabled; }
    
    // 设置零拷贝传输配置
    void set_zero_copy_enabled(bool enabled) { enable_zero_copy_ = enabled; }
    void set_zero_copy_threshold(size_t threshold) { zero_copy_threshold_ = threshold; }
    
private:
    // 私有构造函数（单例模式）
    ServerConfig();
    
    // 禁用拷贝和赋值
    ServerConfig(const ServerConfig&) = delete;
    ServerConfig& operator=(const ServerConfig&) = delete;
    
    // 解析配置文件
    bool parse_config_file(const std::string& config_file);
    
    // 解析命令行参数
    bool parse_command_line(int argc, char* argv[]);
    
    // 设置默认配置
    void set_defaults();
    
    // 基本配置
    std::string listen_address_;
    uint16_t listen_port_;
    std::string storage_path_;
    int log_level_;
    std::string log_file_;
    size_t max_connections_;
    size_t thread_pool_size_;
    std::chrono::seconds session_timeout_;
    
    // 安全配置
    bool enable_encryption_;
    std::string tls_cert_file_;
    std::string tls_key_file_;
    std::string users_file_;
    
    // 版本控制配置
    bool enable_version_control_;
    size_t max_versions_per_file_;
    
    // TCP优化配置
    bool enable_tcp_optimization_;
    int tcp_send_buffer_size_;
    int tcp_recv_buffer_size_;
    bool enable_tcp_nodelay_;
    
    // 零拷贝传输配置
    bool enable_zero_copy_;
    size_t zero_copy_threshold_;
};

} // namespace server
} // namespace ft
