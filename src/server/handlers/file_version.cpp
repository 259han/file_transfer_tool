#include "file_version.h"
#include <fstream>
#include <json/json.h>  // 使用jsoncpp，需确保项目已包含
#include <sys/stat.h>
#include <sys/types.h>
#include "../core/server_core.h"

namespace ft {
namespace server {

// 单例实现
FileVersionManager& FileVersionManager::instance() {
    static FileVersionManager instance;
    return instance;
}

FileVersionManager::FileVersionManager() {
    // 创建版本文件目录
    version_dir_ = ServerCore::get_storage_path() + "/.versions";
    
    try {
        if (!fs::exists(version_dir_)) {
            fs::create_directories(version_dir_);
            LOG_INFO("Version directory created: %s", version_dir_.c_str());
        }
    } catch (const std::exception& e) {
        LOG_ERROR("Failed to create version directory: %s", e.what());
    }
}

FileVersionManager::~FileVersionManager() {
    // 保存所有版本信息
    std::lock_guard<std::mutex> lock(mutex_);
    
    for (const auto& pair : versions_) {
        try {
            save_versions(pair.first);
        } catch (const std::exception& e) {
            LOG_ERROR("Failed to save version info for %s: %s", pair.first.c_str(), e.what());
        }
    }
}

std::string FileVersionManager::create_version(const std::string& file_path) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    // 规范化文件路径，去掉可能存在的相对路径"../"等
    fs::path norm_path = fs::absolute(fs::path(file_path)).lexically_normal();
    std::string normalized_path = norm_path.string();
    
    // 加载文件版本信息
    load_versions(normalized_path);
    
    // 获取当前最高版本号
    size_t next_version = 1;
    if (!versions_[normalized_path].empty()) {
        // 找到最大版本号
        next_version = std::max_element(
            versions_[normalized_path].begin(),
            versions_[normalized_path].end(),
            [](const FileVersionInfo& a, const FileVersionInfo& b) {
                return a.version < b.version;
            })->version + 1;
    }
    
    // 创建新版本信息
    FileVersionInfo new_version(normalized_path, next_version);
    
    // 构造版本文件路径
    fs::path original_path(normalized_path);
    fs::path version_path = fs::path(version_dir_) / new_version.versioned_name;
    
    // 如果原文件存在，复制一份到版本目录
    if (fs::exists(normalized_path)) {
        try {
            // 确保版本目录存在
            fs::create_directories(version_path.parent_path());
            
            // 复制文件
            fs::copy_file(normalized_path, version_path, fs::copy_options::overwrite_existing);
            LOG_INFO("Created version backup: %s -> %s", 
                    normalized_path.c_str(), version_path.string().c_str());
        } catch (const std::exception& e) {
            LOG_ERROR("Failed to create version backup: %s", e.what());
            return normalized_path;  // 失败时返回原路径
        }
    } else {
        LOG_WARNING("Original file does not exist: %s", normalized_path.c_str());
        // 仍然创建版本记录，但不复制文件（因为不存在）
    }
    
    // 添加到版本列表并保存
    versions_[normalized_path].push_back(new_version);
    save_versions(normalized_path);
    
    LOG_INFO("Created new version %zu for file %s", next_version, normalized_path.c_str());
    
    return normalized_path;  // 返回规范化的原始路径
}

FileVersionInfo FileVersionManager::get_latest_version(const std::string& file_path) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    fs::path norm_path = fs::absolute(fs::path(file_path)).lexically_normal();
    std::string normalized_path = norm_path.string();
    
    load_versions(normalized_path);
    
    if (versions_[normalized_path].empty()) {
        LOG_WARNING("No version found for file %s", normalized_path.c_str());
        return FileVersionInfo();
    }
    
    // 找到最新版本（版本号最大的）
    return *std::max_element(
        versions_[normalized_path].begin(),
        versions_[normalized_path].end(),
        [](const FileVersionInfo& a, const FileVersionInfo& b) {
            return a.version < b.version;
        });
}

std::vector<FileVersionInfo> FileVersionManager::get_all_versions(const std::string& file_path) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    fs::path norm_path = fs::absolute(fs::path(file_path)).lexically_normal();
    std::string normalized_path = norm_path.string();
    
    load_versions(normalized_path);
    
    return versions_[normalized_path];
}

bool FileVersionManager::restore_version(const std::string& file_path, size_t version) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    fs::path norm_path = fs::absolute(fs::path(file_path)).lexically_normal();
    std::string normalized_path = norm_path.string();
    
    load_versions(normalized_path);
    
    // 找到指定版本
    auto it = std::find_if(
        versions_[normalized_path].begin(),
        versions_[normalized_path].end(),
        [version](const FileVersionInfo& info) {
            return info.version == version;
        });
    
    if (it == versions_[normalized_path].end()) {
        LOG_ERROR("Version %zu not found for file %s", version, normalized_path.c_str());
        return false;
    }
    
    // 构造版本文件路径
    fs::path version_path = fs::path(version_dir_) / it->versioned_name;
    
    // 检查版本文件是否存在
    if (!fs::exists(version_path)) {
        LOG_ERROR("Version file not found: %s", version_path.string().c_str());
        return false;
    }
    
    // 在恢复前创建当前文件的新版本备份
    if (fs::exists(normalized_path)) {
        create_version(normalized_path);
    }
    
    try {
        // 确保目标目录存在
        fs::create_directories(fs::path(normalized_path).parent_path());
        
        // 复制版本文件到原始位置
        fs::copy_file(version_path, normalized_path, fs::copy_options::overwrite_existing);
        LOG_INFO("Restored file %s to version %zu", normalized_path.c_str(), version);
        return true;
    } catch (const std::exception& e) {
        LOG_ERROR("Failed to restore version: %s", e.what());
        return false;
    }
}

void FileVersionManager::cleanup_old_versions(const std::string& file_path, size_t keep_count) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    fs::path norm_path = fs::absolute(fs::path(file_path)).lexically_normal();
    std::string normalized_path = norm_path.string();
    
    load_versions(normalized_path);
    
    auto& file_versions = versions_[normalized_path];
    if (file_versions.size() <= keep_count) {
        return;  // 没有足够的版本需要清理
    }
    
    // 按版本号排序
    std::sort(file_versions.begin(), file_versions.end(),
              [](const FileVersionInfo& a, const FileVersionInfo& b) {
                  return a.version > b.version;  // 降序，保留最新的版本
              });
    
    // 保留指定数量的最新版本，删除其余的
    for (size_t i = keep_count; i < file_versions.size(); ++i) {
        fs::path version_path = fs::path(version_dir_) / file_versions[i].versioned_name;
        
        try {
            if (fs::exists(version_path)) {
                fs::remove(version_path);
                LOG_INFO("Removed old version file: %s", version_path.string().c_str());
            }
            
            // 标记为已删除
            file_versions[i].deleted = true;
        } catch (const std::exception& e) {
            LOG_ERROR("Failed to remove old version file: %s, error: %s",
                     version_path.string().c_str(), e.what());
        }
    }
    
    // 从列表中删除已经删除的版本
    file_versions.erase(
        std::remove_if(file_versions.begin(), file_versions.end(),
                     [](const FileVersionInfo& info) { return info.deleted; }),
        file_versions.end());
    
    // 保存更新后的版本信息
    save_versions(normalized_path);
}

std::string FileVersionManager::get_real_path(const std::string& file_path) {
    // 大多数情况下，真实路径就是原始路径
    fs::path norm_path = fs::absolute(fs::path(file_path)).lexically_normal();
    return norm_path.string();
}

void FileVersionManager::load_versions(const std::string& file_path) {
    // 如果已加载，不再重复加载
    if (versions_.find(file_path) != versions_.end()) {
        return;
    }
    
    // 构造版本信息文件路径
    fs::path path(file_path);
    std::string filename = path.filename().string();
    std::string version_file = version_dir_ + "/" + filename + ".versions.json";
    
    // 初始化空列表
    versions_[file_path] = std::vector<FileVersionInfo>();
    
    // 如果版本文件不存在，仅创建空记录
    if (!fs::exists(version_file)) {
        return;
    }
    
    try {
        // 读取版本信息文件
        std::ifstream file(version_file);
        if (!file.is_open()) {
            LOG_ERROR("Failed to open version file: %s", version_file.c_str());
            return;
        }
        
        Json::Value root;
        Json::CharReaderBuilder builder;
        std::string errors;
        
        if (!Json::parseFromStream(builder, file, &root, &errors)) {
            LOG_ERROR("Failed to parse version file %s: %s", version_file.c_str(), errors.c_str());
            return;
        }
        
        // 解析版本信息
        if (root.isArray()) {
            for (const auto& version_json : root) {
                FileVersionInfo info;
                info.filename = version_json["filename"].asString();
                info.versioned_name = version_json["versioned_name"].asString();
                info.timestamp = version_json["timestamp"].asString();
                info.version = version_json["version"].asUInt64();
                info.deleted = version_json["deleted"].asBool();
                
                // 检查实际版本文件是否存在
                fs::path version_path = fs::path(version_dir_) / info.versioned_name;
                if (!fs::exists(version_path)) {
                    info.deleted = true;  // 标记为已删除
                    LOG_WARNING("Version file not found: %s", version_path.string().c_str());
                }
                
                if (!info.deleted) {
                    versions_[file_path].push_back(info);
                }
            }
            
            LOG_INFO("Loaded %zu versions for file %s", versions_[file_path].size(), file_path.c_str());
        }
    } catch (const std::exception& e) {
        LOG_ERROR("Exception while loading versions for %s: %s", file_path.c_str(), e.what());
    }
}

void FileVersionManager::save_versions(const std::string& file_path) {
    try {
        fs::path path(file_path);
        std::string filename = path.filename().string();
        std::string version_file = version_dir_ + "/" + filename + ".versions.json";
        
        // 确保目录存在
        fs::create_directories(fs::path(version_file).parent_path());
        
        // 创建JSON数组
        Json::Value root(Json::arrayValue);
        
        for (const auto& info : versions_[file_path]) {
            Json::Value version;
            version["filename"] = info.filename;
            version["versioned_name"] = info.versioned_name;
            version["timestamp"] = info.timestamp;
            version["version"] = Json::Value::UInt64(info.version);
            version["deleted"] = info.deleted;
            
            root.append(version);
        }
        
        // 写入文件
        std::ofstream file(version_file);
        if (!file.is_open()) {
            LOG_ERROR("Failed to open version file for writing: %s", version_file.c_str());
            return;
        }
        
        Json::StreamWriterBuilder writer;
        writer["indentation"] = "  ";  // 缩进两个空格，提高可读性
        std::string json_str = Json::writeString(writer, root);
        file << json_str;
        
        LOG_INFO("Saved %zu versions for file %s", versions_[file_path].size(), file_path.c_str());
    } catch (const std::exception& e) {
        LOG_ERROR("Exception while saving versions for %s: %s", file_path.c_str(), e.what());
    }
}

} // namespace server
} // namespace ft 