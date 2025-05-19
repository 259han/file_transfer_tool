#pragma once

#include <string>
#include <vector>
#include <cstdint>

namespace ft {
namespace utils {

/**
 * @brief DH密钥参数结构体
 */
struct DHParams {
    std::vector<uint8_t> p;        // 素数p
    std::vector<uint8_t> g;        // 生成元g
    std::vector<uint8_t> public_key; // 公钥
};

/**
 * @brief 加密工具类
 */
class Encryption {
public:
    /**
     * @brief 计算MD5哈希值
     * @param data 数据指针
     * @param len 数据长度
     * @return MD5哈希值的十六进制字符串
     */
    static std::string md5(const void* data, size_t len);
    
    /**
     * @brief 计算MD5哈希值
     * @param str 输入字符串
     * @return MD5哈希值的十六进制字符串
     */
    static std::string md5(const std::string& str);
    
    /**
     * @brief 计算SHA1哈希值
     * @param data 数据指针
     * @param len 数据长度
     * @return SHA1哈希值的十六进制字符串
     */
    static std::string sha1(const void* data, size_t len);
    
    /**
     * @brief 计算SHA1哈希值
     * @param str 输入字符串
     * @return SHA1哈希值的十六进制字符串
     */
    static std::string sha1(const std::string& str);
    
    /**
     * @brief 计算SHA256哈希值
     * @param data 数据指针
     * @param len 数据长度
     * @return SHA256哈希值的十六进制字符串
     */
    static std::string sha256(const void* data, size_t len);
    
    /**
     * @brief 计算SHA256哈希值
     * @param str 输入字符串
     * @return SHA256哈希值的十六进制字符串
     */
    static std::string sha256(const std::string& str);
    
    /**
     * @brief AES加密
     * @param data 明文数据
     * @param key 密钥
     * @param iv 初始向量
     * @return 密文数据
     */
    static std::vector<uint8_t> aes_encrypt(const std::vector<uint8_t>& data, 
                                          const std::vector<uint8_t>& key, 
                                          const std::vector<uint8_t>& iv);
    
    /**
     * @brief AES解密
     * @param data 密文数据
     * @param key 密钥
     * @param iv 初始向量
     * @return 明文数据
     */
    static std::vector<uint8_t> aes_decrypt(const std::vector<uint8_t>& data, 
                                          const std::vector<uint8_t>& key, 
                                          const std::vector<uint8_t>& iv);
    
    /**
     * @brief Base64编码
     * @param data 数据指针
     * @param len 数据长度
     * @return Base64编码后的字符串
     */
    static std::string base64_encode(const void* data, size_t len);
    
    /**
     * @brief Base64编码
     * @param data 数据
     * @return Base64编码后的字符串
     */
    static std::string base64_encode(const std::vector<uint8_t>& data);
    
    /**
     * @brief Base64解码
     * @param str Base64编码的字符串
     * @return 解码后的数据
     */
    static std::vector<uint8_t> base64_decode(const std::string& str);
    
    /**
     * @brief 生成随机字节
     * @param len 长度
     * @return 随机字节数组
     */
    static std::vector<uint8_t> random_bytes(size_t len);
    
    /**
     * @brief 生成随机字符串
     * @param len 长度
     * @return 随机字符串
     */
    static std::string random_string(size_t len);
    
    /**
     * @brief 十六进制编码
     * @param data 数据指针
     * @param len 数据长度
     * @return 十六进制字符串
     */
    static std::string hex_encode(const void* data, size_t len);
    
    /**
     * @brief 十六进制编码
     * @param data 数据
     * @return 十六进制字符串
     */
    static std::string hex_encode(const std::vector<uint8_t>& data);
    
    /**
     * @brief 十六进制解码
     * @param hex 十六进制字符串
     * @return 解码后的数据
     */
    static std::vector<uint8_t> hex_decode(const std::string& hex);
    
    /**
     * @brief 生成DH密钥对
     * @param private_key [输出] 私钥
     * @return DH参数，包括p, g和公钥
     */
    static DHParams generate_dh_params(std::vector<uint8_t>& private_key);
    
    /**
     * @brief 计算DH共享密钥
     * @param params 对方的DH参数
     * @param private_key 本地私钥
     * @return 共享密钥
     */
    static std::vector<uint8_t> compute_dh_shared_key(const DHParams& params, 
                                                     const std::vector<uint8_t>& private_key);
    
    /**
     * @brief 从共享密钥派生出AES密钥和IV
     * @param shared_key DH共享密钥
     * @param key [输出] AES密钥
     * @param iv [输出] AES IV
     */
    static void derive_key_and_iv(const std::vector<uint8_t>& shared_key, 
                                 std::vector<uint8_t>& key, 
                                 std::vector<uint8_t>& iv);
};

} // namespace utils
} // namespace ft 