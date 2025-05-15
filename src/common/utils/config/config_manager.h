#pragma once

#include <string>
#include <map>
#include <mutex>

namespace ft {
namespace utils {

/**
 * @brief 配置管理器类
 */
class ConfigManager {
public:
    /**
     * @brief 获取单例实例
     * @return 配置管理器实例
     */
    static ConfigManager& instance();
    
    /**
     * @brief 加载配置文件
     * @param config_file 配置文件路径
     * @return 是否加载成功
     */
    bool load(const std::string& config_file);
    
    /**
     * @brief 保存配置文件
     * @param config_file 配置文件路径，为空则使用加载时的路径
     * @return 是否保存成功
     */
    bool save(const std::string& config_file = "");
    
    /**
     * @brief 获取字符串配置项
     * @param key 配置项键
     * @param default_value 默认值
     * @return 配置值
     */
    std::string get_string(const std::string& key, const std::string& default_value = "");
    
    /**
     * @brief 获取整数配置项
     * @param key 配置项键
     * @param default_value 默认值
     * @return 配置值
     */
    int get_int(const std::string& key, int default_value = 0);
    
    /**
     * @brief 获取浮点数配置项
     * @param key 配置项键
     * @param default_value 默认值
     * @return 配置值
     */
    double get_double(const std::string& key, double default_value = 0.0);
    
    /**
     * @brief 获取布尔配置项
     * @param key 配置项键
     * @param default_value 默认值
     * @return 配置值
     */
    bool get_bool(const std::string& key, bool default_value = false);
    
    /**
     * @brief 设置配置项
     * @param key 配置项键
     * @param value 配置项值
     */
    void set(const std::string& key, const std::string& value);
    
    /**
     * @brief 设置配置项
     * @param key 配置项键
     * @param value 配置项值
     */
    void set(const std::string& key, int value);
    
    /**
     * @brief 设置配置项
     * @param key 配置项键
     * @param value 配置项值
     */
    void set(const std::string& key, double value);
    
    /**
     * @brief 设置配置项
     * @param key 配置项键
     * @param value 配置项值
     */
    void set(const std::string& key, bool value);
    
    /**
     * @brief 检查配置项是否存在
     * @param key 配置项键
     * @return 是否存在
     */
    bool has(const std::string& key) const;
    
    /**
     * @brief 删除配置项
     * @param key 配置项键
     * @return 是否删除成功
     */
    bool remove(const std::string& key);
    
    /**
     * @brief 清空所有配置项
     */
    void clear();
    
private:
    /**
     * @brief 构造函数
     */
    ConfigManager();
    
    /**
     * @brief 析构函数
     */
    ~ConfigManager();
    
private:
    std::string config_file_;
    std::map<std::string, std::string> config_map_;
    mutable std::mutex mutex_;
};

} // namespace utils
} // namespace ft 