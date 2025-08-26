#include "../common/utils/auth/user_manager.h"
#include "../common/utils/logging/logger.h"
#include "../common/protocol/messages/authentication_message.h"
#include <iostream>
#include <string>
#include <vector>

using namespace ft::utils;
using namespace ft::protocol;

/**
 * @brief 显示帮助信息
 */
void show_help() {
    std::cout << "用户管理工具 - File Transfer Authentication Admin\n";
    std::cout << "用法: user_admin <命令> [参数...]\n\n";
    std::cout << "命令:\n";
    std::cout << "  add-user <用户名> <密码> <权限>    - 添加用户\n";
    std::cout << "  remove-user <用户名>             - 删除用户\n";
    std::cout << "  list-users                       - 列出所有用户\n";
    std::cout << "  change-password <用户名>         - 修改密码\n";
    std::cout << "  set-permissions <用户名> <权限>  - 设置用户权限\n";
    std::cout << "  create-api-key <描述> <权限>     - 创建API密钥\n";
    std::cout << "  revoke-api-key <API密钥>         - 撤销API密钥\n";
    std::cout << "  test-auth <用户名> <密码>        - 测试用户认证\n";
    std::cout << "\n权限值:\n";
    std::cout << "  1 - READ (下载)      2 - WRITE (上传)\n";
    std::cout << "  4 - DELETE (删除)    8 - ADMIN (管理)\n";
    std::cout << "  可以组合多个权限，例如: 3 = READ + WRITE\n";
}

/**
 * @brief 添加用户
 */
bool add_user(const std::vector<std::string>& args) {
    if (args.size() < 3) {
        std::cout << "错误: add-user 需要 <用户名> <密码> <权限> 参数\n";
        return false;
    }
    
    std::string username = args[0];
    std::string password = args[1];
    uint8_t permissions = static_cast<uint8_t>(std::stoi(args[2]));
    
    UserManager& manager = UserManager::instance();
    if (manager.add_user(username, password, permissions)) {
        std::cout << "用户 '" << username << "' 添加成功\n";
        return true;
    } else {
        std::cout << "添加用户失败，可能用户已存在\n";
        return false;
    }
}

/**
 * @brief 删除用户
 */
bool remove_user(const std::vector<std::string>& args) {
    if (args.empty()) {
        std::cout << "错误: remove-user 需要 <用户名> 参数\n";
        return false;
    }
    
    std::string username = args[0];
    UserManager& manager = UserManager::instance();
    
    if (manager.remove_user(username)) {
        std::cout << "用户 '" << username << "' 删除成功\n";
        return true;
    } else {
        std::cout << "删除用户失败，用户可能不存在\n";
        return false;
    }
}

/**
 * @brief 列出所有用户
 */
bool list_users(const std::vector<std::string>& args) {
    (void)args;  // 消除未使用参数警告
    UserManager& manager = UserManager::instance();
    auto users = manager.get_user_list();
    
    if (users.empty()) {
        std::cout << "没有用户\n";
        return true;
    }
    
    std::cout << "用户列表:\n";
    std::cout << "----------------------------------------\n";
    
    for (const std::string& username : users) {
        const UserInfo* info = manager.get_user_info(username);
        if (info) {
            std::cout << "用户名: " << username;
            std::cout << " | 权限: " << static_cast<int>(info->permissions);
            std::cout << " | 状态: " << (info->is_active ? "激活" : "停用");
            std::cout << " | 失败次数: " << info->failed_login_attempts << "\n";
        }
    }
    
    return true;
}

/**
 * @brief 测试用户认证
 */
bool test_auth(const std::vector<std::string>& args) {
    if (args.size() < 2) {
        std::cout << "错误: test-auth 需要 <用户名> <密码> 参数\n";
        return false;
    }
    
    std::string username = args[0];
    std::string password = args[1];
    
    UserManager& manager = UserManager::instance();
    AuthenticationResult result = manager.authenticate_user(username, password);
    
    std::cout << "认证结果: ";
    switch (result) {
        case AuthenticationResult::SUCCESS:
            std::cout << "成功\n";
            std::cout << "用户权限: " << static_cast<int>(manager.get_user_permissions(username)) << "\n";
            break;
        case AuthenticationResult::INVALID_CREDENTIALS:
            std::cout << "密码错误\n";
            break;
        case AuthenticationResult::USER_NOT_FOUND:
            std::cout << "用户不存在\n";
            break;
        case AuthenticationResult::ACCOUNT_LOCKED:
            std::cout << "账户被锁定\n";
            break;
        case AuthenticationResult::SERVER_ERROR:
            std::cout << "服务器错误\n";
            break;
        default:
            std::cout << "未知错误\n";
            break;
    }
    
    return result == AuthenticationResult::SUCCESS;
}

/**
 * @brief 创建API密钥
 */
bool create_api_key(const std::vector<std::string>& args) {
    if (args.size() < 2) {
        std::cout << "错误: create-api-key 需要 <描述> <权限> 参数\n";
        return false;
    }
    
    std::string description = args[0];
    uint8_t permissions = static_cast<uint8_t>(std::stoi(args[1]));
    
    UserManager& manager = UserManager::instance();
    std::string api_key = manager.generate_api_key(description, permissions);
    
    if (!api_key.empty()) {
        std::cout << "API密钥创建成功:\n";
        std::cout << "密钥: " << api_key << "\n";
        std::cout << "描述: " << description << "\n";
        std::cout << "权限: " << static_cast<int>(permissions) << "\n";
        std::cout << "请妥善保存此密钥，它不会再次显示！\n";
        return true;
    } else {
        std::cout << "创建API密钥失败\n";
        return false;
    }
}

int main(int argc, char* argv[]) {
    if (argc < 2) {
        show_help();
        return 1;
    }
    
    // 初始化用户管理器
    UserManager& manager = UserManager::instance();
    if (!manager.initialize("data/auth/users.json", "data/auth/api_keys.json")) {
        std::cerr << "初始化用户管理器失败\n";
        return 1;
    }
    
    std::string command = argv[1];
    std::vector<std::string> args;
    
    for (int i = 2; i < argc; ++i) {
        args.push_back(argv[i]);
    }
    
    bool success = false;
    
    if (command == "add-user") {
        success = add_user(args);
    } else if (command == "remove-user") {
        success = remove_user(args);
    } else if (command == "list-users") {
        success = list_users(args);
    } else if (command == "test-auth") {
        success = test_auth(args);
    } else if (command == "create-api-key") {
        success = create_api_key(args);
    } else if (command == "help" || command == "--help" || command == "-h") {
        show_help();
        return 0;
    } else {
        std::cout << "未知命令: " << command << "\n";
        show_help();
        return 1;
    }
    
    return success ? 0 : 1;
} 