#pragma once

#include <string>
#include <vector>
#include <cstdint>

namespace ft {
namespace utils {

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
     * @return Base64编码字符串
     */
    static std::string base64_encode(const void* data, size_t len);
    
    /**
     * @brief Base64编码
     * @param data 输入数据
     * @return Base64编码字符串
     */
    static std::string base64_encode(const std::vector<uint8_t>& data);
    
    /**
     * @brief Base64解码
     * @param str Base64编码字符串
     * @return 解码数据
     */
    static std::vector<uint8_t> base64_decode(const std::string& str);
    
    /**
     * @brief 生成随机字节
     * @param len 长度
     * @return 随机字节数组
     */
    static std::vector<uint8_t> random_bytes(size_t len);
    
    /**
     * @brief 十六进制编码
     * @param data 数据指针
     * @param len 数据长度
     * @return 十六进制字符串
     */
    static std::string hex_encode(const void* data, size_t len);
    
    /**
     * @brief 十六进制编码
     * @param data 输入数据
     * @return 十六进制字符串
     */
    static std::string hex_encode(const std::vector<uint8_t>& data);
    
    /**
     * @brief 十六进制解码
     * @param str 十六进制字符串
     * @return 解码数据
     */
    static std::vector<uint8_t> hex_decode(const std::string& str);
};

} // namespace utils
} // namespace ft 