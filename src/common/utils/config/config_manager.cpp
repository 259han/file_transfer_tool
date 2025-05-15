#include "config_manager.h"
#include <fstream>
#include <sstream>
#include <iostream>

namespace ft {
namespace utils {

ConfigManager& ConfigManager::instance() {
    static ConfigManager instance;
    return instance;
}

ConfigManager::ConfigManager()
    : config_file_(""),
      config_map_(),
      mutex_() {
}

ConfigManager::~ConfigManager() {
    // 自动保存配置
    if (!config_file_.empty()) {
        save();
    }
}

bool ConfigManager::load(const std::string& config_file) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    config_file_ = config_file;
    config_map_.clear();
    
    std::ifstream file(config_file);
    if (!file.is_open()) {
        return false;
    }
    
    std::string line;
    while (std::getline(file, line)) {
        // 忽略空行和注释行
        if (line.empty() || line[0] == '#') {
            continue;
        }
        
        // 解析键值对
        size_t pos = line.find('=');
        if (pos != std::string::npos) {
            std::string key = line.substr(0, pos);
            std::string value = line.substr(pos + 1);
            
            // 移除前后空格
            key.erase(0, key.find_first_not_of(" \t"));
            key.erase(key.find_last_not_of(" \t") + 1);
            value.erase(0, value.find_first_not_of(" \t"));
            value.erase(value.find_last_not_of(" \t") + 1);
            
            config_map_[key] = value;
        }
    }
    
    file.close();
    return true;
}

bool ConfigManager::save(const std::string& config_file) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    std::string file_path = config_file.empty() ? config_file_ : config_file;
    if (file_path.empty()) {
        return false;
    }
    
    std::ofstream file(file_path);
    if (!file.is_open()) {
        return false;
    }
    
    // 写入配置项
    for (const auto& pair : config_map_) {
        file << pair.first << " = " << pair.second << std::endl;
    }
    
    file.close();
    return true;
}

std::string ConfigManager::get_string(const std::string& key, const std::string& default_value) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    auto it = config_map_.find(key);
    if (it != config_map_.end()) {
        return it->second;
    }
    
    return default_value;
}

int ConfigManager::get_int(const std::string& key, int default_value) {
    std::string value = get_string(key, "");
    if (value.empty()) {
        return default_value;
    }
    
    try {
        return std::stoi(value);
    } catch (...) {
        return default_value;
    }
}

double ConfigManager::get_double(const std::string& key, double default_value) {
    std::string value = get_string(key, "");
    if (value.empty()) {
        return default_value;
    }
    
    try {
        return std::stod(value);
    } catch (...) {
        return default_value;
    }
}

bool ConfigManager::get_bool(const std::string& key, bool default_value) {
    std::string value = get_string(key, "");
    if (value.empty()) {
        return default_value;
    }
    
    // 转换为小写
    for (auto& c : value) {
        c = std::tolower(c);
    }
    
    // 判断是否为真值
    if (value == "true" || value == "yes" || value == "1" || value == "on") {
        return true;
    }
    
    // 判断是否为假值
    if (value == "false" || value == "no" || value == "0" || value == "off") {
        return false;
    }
    
    return default_value;
}

void ConfigManager::set(const std::string& key, const std::string& value) {
    std::lock_guard<std::mutex> lock(mutex_);
    config_map_[key] = value;
}

void ConfigManager::set(const std::string& key, int value) {
    std::lock_guard<std::mutex> lock(mutex_);
    config_map_[key] = std::to_string(value);
}

void ConfigManager::set(const std::string& key, double value) {
    std::lock_guard<std::mutex> lock(mutex_);
    config_map_[key] = std::to_string(value);
}

void ConfigManager::set(const std::string& key, bool value) {
    std::lock_guard<std::mutex> lock(mutex_);
    config_map_[key] = value ? "true" : "false";
}

bool ConfigManager::has(const std::string& key) const {
    std::lock_guard<std::mutex> lock(mutex_);
    return config_map_.find(key) != config_map_.end();
}

bool ConfigManager::remove(const std::string& key) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    auto it = config_map_.find(key);
    if (it != config_map_.end()) {
        config_map_.erase(it);
        return true;
    }
    
    return false;
}

void ConfigManager::clear() {
    std::lock_guard<std::mutex> lock(mutex_);
    config_map_.clear();
}

} // namespace utils
} // namespace ft 