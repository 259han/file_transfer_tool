#include "user_manager.h"
#include "../crypto/encryption.h"
#include "../logging/logger.h"
#include <fstream>
#include <random>
#include <iomanip>
#include <sstream>
#include <openssl/sha.h>
#include <openssl/evp.h>
#include <openssl/rand.h>

namespace ft {
namespace utils {

// 静态成员定义
const int UserManager::MAX_FAILED_ATTEMPTS;
const int UserManager::LOCKOUT_DURATION_MINUTES;

UserManager::UserManager() {
}

UserManager::~UserManager() {
    save_users();
    save_api_keys();
}

UserManager& UserManager::instance() {
    static UserManager instance_;
    return instance_;
}

bool UserManager::initialize(const std::string& users_file, const std::string& api_keys_file) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    users_file_ = users_file;
    api_keys_file_ = api_keys_file;
    
    // 加载用户数据
    if (!load_users()) {
        LOG_WARNING("Failed to load users from %s", users_file_.c_str());
    }
    
    // 加载API密钥数据
    if (!load_api_keys()) {
        LOG_WARNING("Failed to load API keys from %s", api_keys_file_.c_str());
    }
    
    // 如果没有管理员账户，创建默认管理员（不需要重复加锁）
    bool has_admin = false;
    for (const auto& pair : users_) {
        const UserInfo& user = pair.second;
        if (user.is_active && (user.permissions & static_cast<uint8_t>(protocol::UserPermission::ADMIN))) {
            has_admin = true;
            break;
        }
    }
    
    if (!has_admin) {
        LOG_INFO("No admin user found, creating default admin account");
        // 直接在这里创建管理员，避免调用会产生死锁的函数
        if (users_.find("admin") == users_.end()) {
            UserInfo user_info;
            user_info.username = "admin";
            user_info.salt = generate_salt();
            if (user_info.salt.empty()) {
                LOG_ERROR("Failed to generate salt for default admin");
                return false;
            }
            user_info.password_hash = hash_password("admin", user_info.salt);
            user_info.permissions = static_cast<uint8_t>(protocol::UserPermission::READ) |
                                   static_cast<uint8_t>(protocol::UserPermission::WRITE) |
                                   static_cast<uint8_t>(protocol::UserPermission::DELETE) |
                                   static_cast<uint8_t>(protocol::UserPermission::ADMIN);
            user_info.is_active = true;
            user_info.failed_login_attempts = 0;
            
            users_["admin"] = user_info;
            
            LOG_INFO("Default admin user created");
            if (!save_users()) {
                LOG_ERROR("Failed to save default admin user");
                return false;
            }
        }
    }
    
    return true;
}

protocol::AuthenticationResult UserManager::authenticate_user(const std::string& username, const std::string& password) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    auto it = users_.find(username);
    if (it == users_.end()) {
        return protocol::AuthenticationResult::USER_NOT_FOUND;
    }
    
    UserInfo& user = it->second;
    
    // 检查账户是否激活
    if (!user.is_active) {
        return protocol::AuthenticationResult::ACCOUNT_LOCKED;
    }
    
    // 检查账户是否被锁定
    if (is_account_locked(user)) {
        return protocol::AuthenticationResult::ACCOUNT_LOCKED;
    }
    
    // 验证密码
    if (!verify_password(password, user.password_hash, user.salt)) {
        handle_login_failure(username);
        return protocol::AuthenticationResult::INVALID_CREDENTIALS;
    }
    
    // 认证成功
    handle_login_success(username);
    return protocol::AuthenticationResult::SUCCESS;
}

protocol::AuthenticationResult UserManager::authenticate_api_key(const std::string& api_key) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    auto it = api_keys_.find(api_key);
    if (it == api_keys_.end()) {
        return protocol::AuthenticationResult::INVALID_CREDENTIALS;
    }
    
    ApiKeyInfo& key_info = it->second;
    
    // 检查API密钥是否激活
    if (!key_info.is_active) {
        return protocol::AuthenticationResult::ACCOUNT_LOCKED;
    }
    
    // 检查是否过期
    auto now = std::chrono::system_clock::now();
    if (key_info.expires_at != std::chrono::system_clock::time_point{} && now > key_info.expires_at) {
        return protocol::AuthenticationResult::INVALID_CREDENTIALS;
    }
    
    // 更新最后使用时间
    key_info.last_used = now;
    
    return protocol::AuthenticationResult::SUCCESS;
}

bool UserManager::is_account_locked(const UserInfo& user_info) {
    if (user_info.failed_login_attempts < MAX_FAILED_ATTEMPTS) {
        return false;
    }
    
    auto now = std::chrono::system_clock::now();
    return now < user_info.locked_until;
}

void UserManager::handle_login_failure(const std::string& username) {
    auto it = users_.find(username);
    if (it == users_.end()) {
        return;
    }
    
    UserInfo& user = it->second;
    user.failed_login_attempts++;
    
    if (user.failed_login_attempts >= MAX_FAILED_ATTEMPTS) {
        auto now = std::chrono::system_clock::now();
        user.locked_until = now + std::chrono::minutes(LOCKOUT_DURATION_MINUTES);
        LOG_WARNING("User account locked: %s", username.c_str());
    }
}

void UserManager::handle_login_success(const std::string& username) {
    auto it = users_.find(username);
    if (it == users_.end()) {
        return;
    }
    
    UserInfo& user = it->second;
    user.failed_login_attempts = 0;
    user.last_login = std::chrono::system_clock::now();
    user.locked_until = std::chrono::system_clock::time_point{};
}

std::string UserManager::generate_salt() {
    unsigned char salt_bytes[16];
    if (RAND_bytes(salt_bytes, sizeof(salt_bytes)) != 1) {
        return "";
    }
    
    std::stringstream ss;
    for (int i = 0; i < 16; ++i) {
        ss << std::hex << std::setw(2) << std::setfill('0') << (int)salt_bytes[i];
    }
    return ss.str();
}

std::string UserManager::hash_password(const std::string& password, const std::string& salt) {
    std::string salted_password = salt + password;
    
    unsigned char hash[SHA256_DIGEST_LENGTH];
    
    // 使用新的 EVP API 替代废弃的 SHA256 API
    EVP_MD_CTX* mdctx = EVP_MD_CTX_new();
    if (!mdctx) {
        throw std::runtime_error("Failed to create EVP_MD_CTX");
    }
    
    if (EVP_DigestInit_ex(mdctx, EVP_sha256(), nullptr) != 1) {
        EVP_MD_CTX_free(mdctx);
        throw std::runtime_error("Failed to initialize SHA256 digest");
    }
    
    if (EVP_DigestUpdate(mdctx, salted_password.c_str(), salted_password.length()) != 1) {
        EVP_MD_CTX_free(mdctx);
        throw std::runtime_error("Failed to update SHA256 digest");
    }
    
    unsigned int hash_len = 0;
    if (EVP_DigestFinal_ex(mdctx, hash, &hash_len) != 1) {
        EVP_MD_CTX_free(mdctx);
        throw std::runtime_error("Failed to finalize SHA256 digest");
    }
    
    EVP_MD_CTX_free(mdctx);
    
    std::stringstream ss;
    for (int i = 0; i < SHA256_DIGEST_LENGTH; ++i) {
        ss << std::hex << std::setw(2) << std::setfill('0') << (int)hash[i];
    }
    return ss.str();
}

bool UserManager::verify_password(const std::string& password, const std::string& hash, const std::string& salt) {
    return hash_password(password, salt) == hash;
}

bool UserManager::has_permission(const std::string& username, protocol::UserPermission permission) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    auto it = users_.find(username);
    if (it == users_.end() || !it->second.is_active) {
        return false;
    }
    
    return (it->second.permissions & static_cast<uint8_t>(permission)) != 0;
}

bool UserManager::has_api_key_permission(const std::string& api_key, protocol::UserPermission permission) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    auto it = api_keys_.find(api_key);
    if (it == api_keys_.end() || !it->second.is_active) {
        return false;
    }
    
    return (it->second.permissions & static_cast<uint8_t>(permission)) != 0;
}

uint8_t UserManager::get_user_permissions(const std::string& username) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    auto it = users_.find(username);
    if (it == users_.end() || !it->second.is_active) {
        return 0;
    }
    
    return it->second.permissions;
}

uint8_t UserManager::get_api_key_permissions(const std::string& api_key) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    auto it = api_keys_.find(api_key);
    if (it == api_keys_.end() || !it->second.is_active) {
        return 0;
    }
    
    return it->second.permissions;
}

bool UserManager::add_user(const std::string& username, const std::string& password, uint8_t permissions) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    // 检查用户是否已存在
    if (users_.find(username) != users_.end()) {
        return false;
    }
    
    // 创建用户信息
    UserInfo user_info;
    user_info.username = username;
    user_info.salt = generate_salt();
    if (user_info.salt.empty()) {
        return false;
    }
    user_info.password_hash = hash_password(password, user_info.salt);
    user_info.permissions = permissions;
    user_info.is_active = true;
    user_info.failed_login_attempts = 0;
    
    users_[username] = user_info;
    
    LOG_INFO("User added: %s", username.c_str());
    return save_users();
}

bool UserManager::remove_user(const std::string& username) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    auto it = users_.find(username);
    if (it == users_.end()) {
        return false;
    }
    
    users_.erase(it);
    LOG_INFO("User removed: %s", username.c_str());
    return save_users();
}

bool UserManager::update_user_permissions(const std::string& username, uint8_t permissions) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    auto it = users_.find(username);
    if (it == users_.end()) {
        return false;
    }
    
    it->second.permissions = permissions;
    LOG_INFO("User permissions updated: %s", username.c_str());
    return save_users();
}

bool UserManager::change_password(const std::string& username, const std::string& old_password, const std::string& new_password) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    auto it = users_.find(username);
    if (it == users_.end()) {
        return false;
    }
    
    UserInfo& user = it->second;
    
    // 验证旧密码
    if (!verify_password(old_password, user.password_hash, user.salt)) {
        return false;
    }
    
    // 生成新的盐值和密码哈希
    user.salt = generate_salt();
    if (user.salt.empty()) {
        return false;
    }
    user.password_hash = hash_password(new_password, user.salt);
    
    LOG_INFO("Password changed for user: %s", username.c_str());
    return save_users();
}

bool UserManager::set_user_active(const std::string& username, bool active) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    auto it = users_.find(username);
    if (it == users_.end()) {
        return false;
    }
    
    it->second.is_active = active;
    LOG_INFO("User %s %s", username.c_str(), active ? "activated" : "deactivated");
    return save_users();
}

std::string UserManager::generate_api_key(const std::string& description, uint8_t permissions, int expires_in_days) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    // 生成随机API密钥
    unsigned char key_bytes[32];
    if (RAND_bytes(key_bytes, sizeof(key_bytes)) != 1) {
        return "";
    }
    
    std::stringstream ss;
    ss << "ftk_"; // 文件传输密钥前缀
    for (int i = 0; i < 32; ++i) {
        ss << std::hex << std::setw(2) << std::setfill('0') << (int)key_bytes[i];
    }
    std::string api_key = ss.str();
    
    // 创建API密钥信息
    ApiKeyInfo key_info;
    key_info.api_key = api_key;
    key_info.description = description;
    key_info.permissions = permissions;
    key_info.is_active = true;
    key_info.created_at = std::chrono::system_clock::now();
    
    if (expires_in_days > 0) {
        key_info.expires_at = key_info.created_at + std::chrono::hours(24 * expires_in_days);
    }
    
    api_keys_[api_key] = key_info;
    
    LOG_INFO("API key generated: %s", description.c_str());
    if (!save_api_keys()) {
        return "";
    }
    
    return api_key;
}

bool UserManager::revoke_api_key(const std::string& api_key) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    auto it = api_keys_.find(api_key);
    if (it == api_keys_.end()) {
        return false;
    }
    
    api_keys_.erase(it);
    LOG_INFO("API key revoked: %.12s...", api_key.c_str());
    return save_api_keys();
}

std::vector<std::string> UserManager::get_user_list() const {
    std::lock_guard<std::mutex> lock(mutex_);
    
    std::vector<std::string> user_list;
    for (const auto& pair : users_) {
        user_list.push_back(pair.first);
    }
    return user_list;
}

const UserInfo* UserManager::get_user_info(const std::string& username) const {
    std::lock_guard<std::mutex> lock(mutex_);
    
    auto it = users_.find(username);
    if (it == users_.end()) {
        return nullptr;
    }
    return &it->second;
}

bool UserManager::has_default_admin() const {
    std::lock_guard<std::mutex> lock(mutex_);
    
    for (const auto& pair : users_) {
        const UserInfo& user = pair.second;
        if (user.is_active && (user.permissions & static_cast<uint8_t>(protocol::UserPermission::ADMIN))) {
            return true;
        }
    }
    return false;
}

bool UserManager::create_default_admin(const std::string& password) {
    return add_user("admin", password, 
                   static_cast<uint8_t>(protocol::UserPermission::READ) |
                   static_cast<uint8_t>(protocol::UserPermission::WRITE) |
                   static_cast<uint8_t>(protocol::UserPermission::DELETE) |
                   static_cast<uint8_t>(protocol::UserPermission::ADMIN));
}

bool UserManager::load_users() {
    std::ifstream file(users_file_);
    if (!file.is_open()) {
        LOG_WARNING("Users file not found, starting with empty user database");
        return true; // 文件不存在不算错误
    }
    
    try {
        // 这里应该使用JSON解析库，为了简化暂时使用简单的格式
        // 实际项目中建议使用nlohmann/json等库
        std::string line;
        while (std::getline(file, line)) {
            if (line.empty() || line[0] == '#') continue;
            
            // 简单的格式：username:password_hash:salt:permissions:is_active
            std::stringstream ss(line);
            std::string username, password_hash, salt, permissions_str, active_str;
            
            if (std::getline(ss, username, ':') &&
                std::getline(ss, password_hash, ':') &&
                std::getline(ss, salt, ':') &&
                std::getline(ss, permissions_str, ':') &&
                std::getline(ss, active_str, ':')) {
                
                UserInfo user_info;
                user_info.username = username;
                user_info.password_hash = password_hash;
                user_info.salt = salt;
                user_info.permissions = static_cast<uint8_t>(std::stoi(permissions_str));
                user_info.is_active = (active_str == "1");
                user_info.failed_login_attempts = 0;
                
                users_[username] = user_info;
            }
        }
        
        LOG_INFO("Loaded %zu users", users_.size());
        return true;
    } catch (const std::exception& e) {
        LOG_ERROR("Failed to load users: %s", e.what());
        return false;
    }
}

bool UserManager::save_users() {
    std::ofstream file(users_file_);
    if (!file.is_open()) {
        LOG_ERROR("Failed to open users file for writing: %s", users_file_.c_str());
        return false;
    }
    
    try {
        file << "# File Transfer Users Database\n";
        file << "# Format: username:password_hash:salt:permissions:is_active\n";
        
        for (const auto& pair : users_) {
            const UserInfo& user = pair.second;
            file << user.username << ":"
                 << user.password_hash << ":"
                 << user.salt << ":"
                 << static_cast<int>(user.permissions) << ":"
                 << (user.is_active ? "1" : "0") << "\n";
        }
        
        return true;
    } catch (const std::exception& e) {
        LOG_ERROR("Failed to save users: %s", e.what());
        return false;
    }
}

bool UserManager::load_api_keys() {
    std::ifstream file(api_keys_file_);
    if (!file.is_open()) {
        LOG_WARNING("API keys file not found, starting with empty API key database");
        return true; // 文件不存在不算错误
    }
    
    try {
        // 简单格式：api_key:description:permissions:is_active:created_timestamp
        std::string line;
        while (std::getline(file, line)) {
            if (line.empty() || line[0] == '#') continue;
            
            std::stringstream ss(line);
            std::string api_key, description, permissions_str, active_str, created_str;
            
            if (std::getline(ss, api_key, ':') &&
                std::getline(ss, description, ':') &&
                std::getline(ss, permissions_str, ':') &&
                std::getline(ss, active_str, ':') &&
                std::getline(ss, created_str, ':')) {
                
                ApiKeyInfo key_info;
                key_info.api_key = api_key;
                key_info.description = description;
                key_info.permissions = static_cast<uint8_t>(std::stoi(permissions_str));
                key_info.is_active = (active_str == "1");
                
                // 解析时间戳
                auto timestamp = std::stoll(created_str);
                key_info.created_at = std::chrono::system_clock::from_time_t(timestamp);
                
                api_keys_[api_key] = key_info;
            }
        }
        
        LOG_INFO("Loaded %zu API keys", api_keys_.size());
        return true;
    } catch (const std::exception& e) {
        LOG_ERROR("Failed to load API keys: %s", e.what());
        return false;
    }
}

bool UserManager::save_api_keys() {
    std::ofstream file(api_keys_file_);
    if (!file.is_open()) {
        LOG_ERROR("Failed to open API keys file for writing: %s", api_keys_file_.c_str());
        return false;
    }
    
    try {
        file << "# File Transfer API Keys Database\n";
        file << "# Format: api_key:description:permissions:is_active:created_timestamp\n";
        
        for (const auto& pair : api_keys_) {
            const ApiKeyInfo& key_info = pair.second;
            auto timestamp = std::chrono::system_clock::to_time_t(key_info.created_at);
            
            file << key_info.api_key << ":"
                 << key_info.description << ":"
                 << static_cast<int>(key_info.permissions) << ":"
                 << (key_info.is_active ? "1" : "0") << ":"
                 << timestamp << "\n";
        }
        
        return true;
    } catch (const std::exception& e) {
        LOG_ERROR("Failed to save API keys: %s", e.what());
        return false;
    }
}
}
} 