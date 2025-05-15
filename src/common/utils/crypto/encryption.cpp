#include "encryption.h"
#include <openssl/md5.h>
#include <openssl/sha.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/aes.h>
#include <sstream>
#include <iomanip>
#include <cstring>

namespace ft {
namespace utils {

std::string Encryption::md5(const void* data, size_t len) {
    if (!data || len == 0) {
        return "";
    }
    
    // 计算MD5
    unsigned char digest[MD5_DIGEST_LENGTH];
    MD5(static_cast<const unsigned char*>(data), len, digest);
    
    // 转换为十六进制字符串
    return hex_encode(digest, sizeof(digest));
}

std::string Encryption::md5(const std::string& str) {
    return md5(str.data(), str.size());
}

std::string Encryption::sha1(const void* data, size_t len) {
    if (!data || len == 0) {
        return "";
    }
    
    // 计算SHA1
    unsigned char digest[SHA_DIGEST_LENGTH];
    SHA1(static_cast<const unsigned char*>(data), len, digest);
    
    // 转换为十六进制字符串
    return hex_encode(digest, sizeof(digest));
}

std::string Encryption::sha1(const std::string& str) {
    return sha1(str.data(), str.size());
}

std::string Encryption::sha256(const void* data, size_t len) {
    if (!data || len == 0) {
        return "";
    }
    
    // 计算SHA256
    unsigned char digest[SHA256_DIGEST_LENGTH];
    SHA256(static_cast<const unsigned char*>(data), len, digest);
    
    // 转换为十六进制字符串
    return hex_encode(digest, sizeof(digest));
}

std::string Encryption::sha256(const std::string& str) {
    return sha256(str.data(), str.size());
}

std::vector<uint8_t> Encryption::aes_encrypt(const std::vector<uint8_t>& data, 
                                           const std::vector<uint8_t>& key, 
                                           const std::vector<uint8_t>& iv) {
    // 暂时返回空实现，完整版可以使用OpenSSL的EVP接口实现
    return {};
}

std::vector<uint8_t> Encryption::aes_decrypt(const std::vector<uint8_t>& data, 
                                           const std::vector<uint8_t>& key, 
                                           const std::vector<uint8_t>& iv) {
    // 暂时返回空实现，完整版可以使用OpenSSL的EVP接口实现
    return {};
}

std::string Encryption::base64_encode(const void* data, size_t len) {
    // 暂时返回空实现，完整版可以使用OpenSSL的EVP_EncodeBlock实现
    return "";
}

std::string Encryption::base64_encode(const std::vector<uint8_t>& data) {
    return base64_encode(data.data(), data.size());
}

std::vector<uint8_t> Encryption::base64_decode(const std::string& str) {
    // 暂时返回空实现，完整版可以使用OpenSSL的EVP_DecodeBlock实现
    return {};
}

std::vector<uint8_t> Encryption::random_bytes(size_t len) {
    std::vector<uint8_t> result(len);
    if (len > 0) {
        // 使用OpenSSL的随机数生成器
        RAND_bytes(result.data(), len);
    }
    return result;
}

std::string Encryption::hex_encode(const void* data, size_t len) {
    if (!data || len == 0) {
        return "";
    }
    
    const unsigned char* bytes = static_cast<const unsigned char*>(data);
    std::stringstream ss;
    ss << std::hex << std::setfill('0');
    
    for (size_t i = 0; i < len; ++i) {
        ss << std::setw(2) << static_cast<int>(bytes[i]);
    }
    
    return ss.str();
}

std::string Encryption::hex_encode(const std::vector<uint8_t>& data) {
    return hex_encode(data.data(), data.size());
}

std::vector<uint8_t> Encryption::hex_decode(const std::string& str) {
    if (str.empty() || str.size() % 2 != 0) {
        return {};
    }
    
    std::vector<uint8_t> result(str.size() / 2);
    
    for (size_t i = 0; i < str.size(); i += 2) {
        std::string byte = str.substr(i, 2);
        result[i / 2] = static_cast<uint8_t>(std::stoi(byte, nullptr, 16));
    }
    
    return result;
}

} // namespace utils
} // namespace ft 