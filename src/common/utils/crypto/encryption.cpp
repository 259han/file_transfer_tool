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
    
    // 使用EVP接口替代直接调用MD5函数（已在OpenSSL 3.0中弃用）
    unsigned char digest[MD5_DIGEST_LENGTH];
    
    // 创建摘要上下文
    EVP_MD_CTX* mdctx = EVP_MD_CTX_new();
    if (!mdctx) {
        return "";
    }
    
    // 初始化MD5上下文
    if (EVP_DigestInit_ex(mdctx, EVP_md5(), nullptr) != 1) {
        EVP_MD_CTX_free(mdctx);
        return "";
    }
    
    // 更新摘要计算
    if (EVP_DigestUpdate(mdctx, data, len) != 1) {
        EVP_MD_CTX_free(mdctx);
        return "";
    }
    
    // 完成摘要计算
    unsigned int digest_len = 0;
    if (EVP_DigestFinal_ex(mdctx, digest, &digest_len) != 1) {
        EVP_MD_CTX_free(mdctx);
        return "";
    }
    
    // 清理上下文
    EVP_MD_CTX_free(mdctx);
    
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
    // 使用OpenSSL的EVP接口实现AES-256-CBC加密
    if (data.empty() || key.size() != 32 || iv.size() != 16) {
        // AES-256 需要32字节密钥和16字节IV
        return {};
    }
    
    // 创建加密上下文
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        return {};
    }
    
    // 初始化加密操作
    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), nullptr, key.data(), iv.data()) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return {};
    }
    
    // 分配输出缓冲区
    // 密文可能比明文长，需要额外的块大小空间
    std::vector<uint8_t> encrypted(data.size() + AES_BLOCK_SIZE);
    int len = 0;
    int total_len = 0;
    
    // 加密数据
    if (EVP_EncryptUpdate(ctx, encrypted.data(), &len, data.data(), data.size()) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return {};
    }
    total_len = len;
    
    // 完成加密
    if (EVP_EncryptFinal_ex(ctx, encrypted.data() + len, &len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return {};
    }
    total_len += len;
    
    // 清理
    EVP_CIPHER_CTX_free(ctx);
    
    // 调整输出大小
    encrypted.resize(total_len);
    return encrypted;
}

std::vector<uint8_t> Encryption::aes_decrypt(const std::vector<uint8_t>& data, 
                                           const std::vector<uint8_t>& key, 
                                           const std::vector<uint8_t>& iv) {
    // 使用OpenSSL的EVP接口实现AES-256-CBC解密
    if (data.empty() || key.size() != 32 || iv.size() != 16) {
        // AES-256 需要32字节密钥和16字节IV
        return {};
    }
    
    // 创建解密上下文
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        return {};
    }
    
    // 初始化解密操作
    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), nullptr, key.data(), iv.data()) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return {};
    }
    
    // 分配输出缓冲区
    std::vector<uint8_t> decrypted(data.size());
    int len = 0;
    int total_len = 0;
    
    // 解密数据
    if (EVP_DecryptUpdate(ctx, decrypted.data(), &len, data.data(), data.size()) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return {};
    }
    total_len = len;
    
    // 完成解密
    if (EVP_DecryptFinal_ex(ctx, decrypted.data() + len, &len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return {};
    }
    total_len += len;
    
    // 清理
    EVP_CIPHER_CTX_free(ctx);
    
    // 调整输出大小
    decrypted.resize(total_len);
    return decrypted;
}

std::string Encryption::base64_encode(const void* data, size_t len) {
    if (!data || len == 0) {
        return "";
    }
    
    // 使用OpenSSL的EVP_EncodeBlock实现Base64编码
    // Base64编码后的长度 = (原始长度 + 2) / 3 * 4
    size_t encoded_len = ((len + 2) / 3) * 4;
    std::vector<unsigned char> encoded(encoded_len + 1); // +1 用于存储终止符
    
    // 执行Base64编码
    encoded_len = EVP_EncodeBlock(encoded.data(), 
                                  static_cast<const unsigned char*>(data), 
                                  len);
    
    // 确保字符串正确终止
    encoded[encoded_len] = '\0';
    
    return std::string(reinterpret_cast<char*>(encoded.data()), encoded_len);
}

std::string Encryption::base64_encode(const std::vector<uint8_t>& data) {
    return base64_encode(data.data(), data.size());
}

std::vector<uint8_t> Encryption::base64_decode(const std::string& str) {
    if (str.empty()) {
        return {};
    }
    
    // 使用OpenSSL的EVP_DecodeBlock实现Base64解码
    // Base64解码后的最大长度 = 原始编码长度 * 3 / 4
    size_t max_decoded_len = (str.length() * 3) / 4 + 1; // +1 用于安全裕度
    std::vector<unsigned char> decoded(max_decoded_len);
    
    // 执行Base64解码
    int decoded_len = EVP_DecodeBlock(decoded.data(), 
                                      reinterpret_cast<const unsigned char*>(str.c_str()), 
                                      str.length());
    
    if (decoded_len <= 0) {
        return {};
    }
    
    // 处理Base64填充问题
    // 如果原始字符串末尾有'='符号，则需要调整长度
    if (str.length() > 0 && str[str.length() - 1] == '=') {
        if (str.length() > 1 && str[str.length() - 2] == '=') {
            decoded_len -= 2; // 有两个等号，减去2
        } else {
            decoded_len -= 1; // 有一个等号，减去1
        }
    }
    
    // 调整输出大小
    decoded.resize(decoded_len > 0 ? decoded_len : 0);
    return decoded;
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