#pragma once

#include "../../protocol/messages/authentication_message.h"
#include <string>
#include <map>
#include <vector>
#include <mutex>
#include <chrono>

namespace ft {
namespace utils {

/**
 * @brief 用户信息结构体
 */
struct UserInfo {
    std::string username;
    std::string password_hash;
    std::string salt;
    uint8_t permissions;
    bool is_active;
    std::chrono::system_clock::time_point last_login;
    int failed_login_attempts;
    std::chrono::system_clock::time_point locked_until;
    
    UserInfo() : permissions(0), is_active(true), failed_login_attempts(0) {}
};

/**
 * @brief API密钥信息结构体
 */
struct ApiKeyInfo {
    std::string api_key;
    std::string description;
    uint8_t permissions;
    bool is_active;
    std::chrono::system_clock::time_point created_at;
    std::chrono::system_clock::time_point expires_at;
    std::chrono::system_clock::time_point last_used;
    
    ApiKeyInfo() : permissions(0), is_active(true) {}
};

/**
 * @brief 用户管理器类
 */
class UserManager {
public:
    /**
     * @brief 获取单例实例
     * @return 用户管理器实例
     */
    static UserManager& instance();
    
    /**
     * @brief 初始化用户管理器
     * @param users_file 用户文件路径
     * @param api_keys_file API密钥文件路径
     * @return 是否初始化成功
     */
    bool initialize(const std::string& users_file = "users.json", 
                   const std::string& api_keys_file = "api_keys.json");
    
    /**
     * @brief 加载用户数据
     * @return 是否加载成功
     */
    bool load_users();
    
    /**
     * @brief 保存用户数据
     * @return 是否保存成功
     */
    bool save_users();
    
    /**
     * @brief 加载API密钥数据
     * @return 是否加载成功
     */
    bool load_api_keys();
    
    /**
     * @brief 保存API密钥数据
     * @return 是否保存成功
     */
    bool save_api_keys();
    
    /**
     * @brief 用户名密码认证
     * @param username 用户名
     * @param password 密码（明文）
     * @return 认证结果
     */
    protocol::AuthenticationResult authenticate_user(const std::string& username, const std::string& password);
    
    /**
     * @brief API密钥认证
     * @param api_key API密钥
     * @return 认证结果
     */
    protocol::AuthenticationResult authenticate_api_key(const std::string& api_key);
    
    /**
     * @brief 检查用户权限
     * @param username 用户名
     * @param permission 权限类型
     * @return 是否有权限
     */
    bool has_permission(const std::string& username, protocol::UserPermission permission);
    
    /**
     * @brief 检查API密钥权限
     * @param api_key API密钥
     * @param permission 权限类型
     * @return 是否有权限
     */
    bool has_api_key_permission(const std::string& api_key, protocol::UserPermission permission);
    
    /**
     * @brief 获取用户权限
     * @param username 用户名
     * @return 权限位掩码
     */
    uint8_t get_user_permissions(const std::string& username);
    
    /**
     * @brief 获取API密钥权限
     * @param api_key API密钥
     * @return 权限位掩码
     */
    uint8_t get_api_key_permissions(const std::string& api_key);
    
    /**
     * @brief 添加用户
     * @param username 用户名
     * @param password 密码（明文）
     * @param permissions 权限位掩码
     * @return 是否添加成功
     */
    bool add_user(const std::string& username, const std::string& password, uint8_t permissions);
    
    /**
     * @brief 删除用户
     * @param username 用户名
     * @return 是否删除成功
     */
    bool remove_user(const std::string& username);
    
    /**
     * @brief 更新用户权限
     * @param username 用户名
     * @param permissions 新的权限位掩码
     * @return 是否更新成功
     */
    bool update_user_permissions(const std::string& username, uint8_t permissions);
    
    /**
     * @brief 更改用户密码
     * @param username 用户名
     * @param old_password 旧密码（明文）
     * @param new_password 新密码（明文）
     * @return 是否更改成功
     */
    bool change_password(const std::string& username, const std::string& old_password, const std::string& new_password);
    
    /**
     * @brief 激活/停用用户
     * @param username 用户名
     * @param active 是否激活
     * @return 是否更新成功
     */
    bool set_user_active(const std::string& username, bool active);
    
    /**
     * @brief 生成API密钥
     * @param description 描述
     * @param permissions 权限位掩码
     * @param expires_in_days 过期天数（0表示永不过期）
     * @return API密钥字符串，失败时返回空字符串
     */
    std::string generate_api_key(const std::string& description, uint8_t permissions, int expires_in_days = 0);
    
    /**
     * @brief 撤销API密钥
     * @param api_key API密钥
     * @return 是否撤销成功
     */
    bool revoke_api_key(const std::string& api_key);
    
    /**
     * @brief 获取所有用户列表
     * @return 用户名列表
     */
    std::vector<std::string> get_user_list() const;
    
    /**
     * @brief 获取用户信息
     * @param username 用户名
     * @return 用户信息，如果用户不存在返回nullptr
     */
    const UserInfo* get_user_info(const std::string& username) const;
    
    /**
     * @brief 检查是否为默认管理员账户
     * @return 是否存在默认管理员
     */
    bool has_default_admin() const;
    
    /**
     * @brief 创建默认管理员账户
     * @param password 管理员密码
     * @return 是否创建成功
     */
    bool create_default_admin(const std::string& password = "admin");

private:
    /**
     * @brief 构造函数
     */
    UserManager();
    
    /**
     * @brief 析构函数
     */
    ~UserManager();
    
    /**
     * @brief 生成密码哈希
     * @param password 明文密码
     * @param salt 盐值
     * @return 密码哈希
     */
    std::string hash_password(const std::string& password, const std::string& salt);
    
    /**
     * @brief 生成随机盐值
     * @return 盐值
     */
    std::string generate_salt();
    
    /**
     * @brief 验证密码
     * @param password 明文密码
     * @param hash 存储的哈希
     * @param salt 盐值
     * @return 是否匹配
     */
    bool verify_password(const std::string& password, const std::string& hash, const std::string& salt);
    
    /**
     * @brief 检查账户是否被锁定
     * @param user_info 用户信息
     * @return 是否被锁定
     */
    bool is_account_locked(const UserInfo& user_info);
    
    /**
     * @brief 处理登录失败
     * @param username 用户名
     */
    void handle_login_failure(const std::string& username);
    
    /**
     * @brief 处理登录成功
     * @param username 用户名
     */
    void handle_login_success(const std::string& username);

private:
    std::string users_file_;
    std::string api_keys_file_;
    std::map<std::string, UserInfo> users_;
    std::map<std::string, ApiKeyInfo> api_keys_;
    mutable std::mutex mutex_;
    
    // 安全配置
    static const int MAX_FAILED_ATTEMPTS = 5;
    static const int LOCKOUT_DURATION_MINUTES = 30;
};

} // namespace utils
} // namespace ft 