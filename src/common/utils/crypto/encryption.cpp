#include "encryption.h"
#include <openssl/md5.h>
#include <openssl/sha.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/aes.h>
#include <openssl/dh.h>
#include <openssl/bn.h>
#include <openssl/kdf.h>
#include <sstream>
#include <iomanip>
#include <cstring>
#include <random>

namespace ft {
namespace utils {

// 使用预先计算的DH参数，避免每次生成大素数带来的性能开销
// OpenSSL提供的预定义DH参数组（这些数值是实际使用的DH参数的十六进制表示）
// 使用2048位参数
static const unsigned char rfc3526_prime_2048[] = {
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xC9, 0x0F, 0xDA, 0xA2, 
    0x21, 0x68, 0xC2, 0x34, 0xC4, 0xC6, 0x62, 0x8B, 0x80, 0xDC, 0x1C, 0xD1,
    0x29, 0x02, 0x4E, 0x08, 0x8A, 0x67, 0xCC, 0x74, 0x02, 0x0B, 0xBE, 0xA6, 
    0x3B, 0x13, 0x9B, 0x22, 0x51, 0x4A, 0x08, 0x79, 0x8E, 0x34, 0x04, 0xDD,
    0xEF, 0x95, 0x19, 0xB3, 0xCD, 0x3A, 0x43, 0x1B, 0x30, 0x2B, 0x0A, 0x6D, 
    0xF2, 0x5F, 0x14, 0x37, 0x4F, 0xE1, 0x35, 0x6D, 0x6D, 0x51, 0xC2, 0x45,
    0xE4, 0x85, 0xB5, 0x76, 0x62, 0x5E, 0x7E, 0xC6, 0xF4, 0x4C, 0x42, 0xE9, 
    0xA6, 0x37, 0xED, 0x6B, 0x0B, 0xFF, 0x5C, 0xB6, 0xF4, 0x06, 0xB7, 0xED,
    0xEE, 0x38, 0x6B, 0xFB, 0x5A, 0x89, 0x9F, 0xA5, 0xAE, 0x9F, 0x24, 0x11, 
    0x7C, 0x4B, 0x1F, 0xE6, 0x49, 0x28, 0x66, 0x51, 0xEC, 0xE4, 0x5B, 0x3D,
    0xC2, 0x00, 0x7C, 0xB8, 0xA1, 0x63, 0xBF, 0x05, 0x98, 0xDA, 0x48, 0x36, 
    0x1C, 0x55, 0xD3, 0x9A, 0x69, 0x16, 0x3F, 0xA8, 0xFD, 0x24, 0xCF, 0x5F,
    0x83, 0x65, 0x5D, 0x23, 0xDC, 0xA3, 0xAD, 0x96, 0x1C, 0x62, 0xF3, 0x56, 
    0x20, 0x85, 0x52, 0xBB, 0x9E, 0xD5, 0x29, 0x07, 0x70, 0x96, 0x96, 0x6D,
    0x67, 0x0C, 0x35, 0x4E, 0x4A, 0xBC, 0x98, 0x04, 0xF1, 0x74, 0x6C, 0x08, 
    0xCA, 0x18, 0x21, 0x7C, 0x32, 0x90, 0x5E, 0x46, 0x2E, 0x36, 0xCE, 0x3B,
    0xE3, 0x9E, 0x77, 0x2C, 0x18, 0x0E, 0x86, 0x03, 0x9B, 0x27, 0x83, 0xA2, 
    0xEC, 0x07, 0xA2, 0x8F, 0xB5, 0xC5, 0x5D, 0xF0, 0x6F, 0x4C, 0x52, 0xC9,
    0xDE, 0x2B, 0xCB, 0xF6, 0x95, 0x58, 0x17, 0x18, 0x39, 0x95, 0x49, 0x7C, 
    0xEA, 0x95, 0x6A, 0xE5, 0x15, 0xD2, 0x26, 0x18, 0x98, 0xFA, 0x05, 0x10,
    0x15, 0x72, 0x8E, 0x5A, 0x8A, 0xAA, 0xC4, 0x2D, 0xAD, 0x33, 0x17, 0x0D, 
    0x04, 0x50, 0x7A, 0x33, 0xA8, 0x55, 0x21, 0xAB, 0xDF, 0x1C, 0xBA, 0x64,
    0xEC, 0xFB, 0x85, 0x04, 0x58, 0xDB, 0xEF, 0x0A, 0x8A, 0xEA, 0x71, 0x57, 
    0x5D, 0x06, 0x0C, 0x7D, 0xB3, 0x97, 0x0F, 0x85, 0xA6, 0xE1, 0xE4, 0xC7,
    0xAB, 0xF5, 0xAE, 0x8C, 0xDB, 0x09, 0x33, 0xD7, 0x1E, 0x8C, 0x94, 0xE0, 
    0x4A, 0x25, 0x61, 0x9D, 0xCE, 0xE3, 0xD2, 0x26, 0x1A, 0xD2, 0xEE, 0x6B,
    0xF1, 0x2F, 0xFA, 0x06, 0xD9, 0x8A, 0x08, 0x64, 0xD8, 0x76, 0x02, 0x73,
    0x3E, 0xC8, 0x6A, 0x64, 0x52, 0x1F, 0x2B, 0x18, 0x17, 0x7B, 0x20, 0x0C,
    0xBB, 0xE1, 0x17, 0x57, 0x7A, 0x61, 0x5D, 0x6C, 0x77, 0x09, 0x88, 0xC0,
    0xBA, 0xD9, 0x46, 0xE2, 0x08, 0xE2, 0x4F, 0xA0, 0x74, 0xE5, 0xAB, 0x31,
    0x43, 0xDB, 0x5B, 0xFC, 0xE0, 0xFD, 0x10, 0x8E, 0x4B, 0x82, 0xD1, 0x20,
    0xA9, 0x3A, 0xD2, 0xCA, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF
};

// 2是标准生成元
static const unsigned char generator[] = { 0x02 };

/**
 * @brief 使用预定义的DH参数创建密钥对
 * @param private_key [输出] 私钥
 * @return DH参数
 */
static DHParams create_dh_params_from_predefined(std::vector<uint8_t>& private_key) {
    DHParams params;
    
    // 使用预定义的DH参数创建密钥对
    DH* dh = DH_new();
    if (!dh) {
        return params;
    }
    
    // 设置预定义的参数
    BIGNUM* p = BN_bin2bn(rfc3526_prime_2048, sizeof(rfc3526_prime_2048), nullptr);
    BIGNUM* g = BN_bin2bn(generator, sizeof(generator), nullptr);
    
    if (!p || !g) {
        if (p) BN_free(p);
        if (g) BN_free(g);
        DH_free(dh);
        return params;
    }
    
    // 设置DH参数
    if (DH_set0_pqg(dh, p, nullptr, g) != 1) {
        BN_free(p);
        BN_free(g);
        DH_free(dh);
        return params;
    }
    
    // 生成密钥对
    if (DH_generate_key(dh) != 1) {
        DH_free(dh);
        return params;
    }
    
    // 获取DH参数
    const BIGNUM* out_p = nullptr;
    const BIGNUM* out_g = nullptr;
    const BIGNUM* pub_key = nullptr;
    const BIGNUM* priv_key = nullptr;
    
    // 使用DH_get0_*函数获取参数
    DH_get0_pqg(dh, &out_p, nullptr, &out_g);
    DH_get0_key(dh, &pub_key, &priv_key);
    
    if (!out_p || !out_g || !pub_key || !priv_key) {
        DH_free(dh);
        return params;
    }
    
    // 转换为字节数组
    params.p.resize(BN_num_bytes(out_p));
    BN_bn2bin(out_p, params.p.data());
    
    params.g.resize(BN_num_bytes(out_g));
    BN_bn2bin(out_g, params.g.data());
    
    params.public_key.resize(BN_num_bytes(pub_key));
    BN_bn2bin(pub_key, params.public_key.data());
    
    private_key.resize(BN_num_bytes(priv_key));
    BN_bn2bin(priv_key, private_key.data());
    
    // 清理
    DH_free(dh);
    
    return params;
}

// 修改原有的generate_dh_params方法，使用预计算的参数
DHParams Encryption::generate_dh_params(std::vector<uint8_t>& private_key) {
    // 使用预定义参数更快速地创建密钥对，而不是每次生成新的DH参数
    return create_dh_params_from_predefined(private_key);
    
    /* 原始动态生成DH参数的代码保留在注释中，以备需要
    DHParams params;
    
    // 创建DH上下文
    DH* dh = DH_new();
    if (!dh) {
        return params;
    }
    
    // 使用2048位参数
    if (DH_generate_parameters_ex(dh, 2048, DH_GENERATOR_2, nullptr) != 1) {
        DH_free(dh);
        return params;
    }
    
    // 生成密钥对
    if (DH_generate_key(dh) != 1) {
        DH_free(dh);
        return params;
    }
    
    ... 其余代码保持不变 ...
    
    return params;
    */
}

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

std::vector<uint8_t> Encryption::hex_decode(const std::string& hex) {
    if (hex.empty() || hex.size() % 2 != 0) {
        return {};
    }
    
    std::vector<uint8_t> result(hex.size() / 2);
    
    for (size_t i = 0; i < hex.size(); i += 2) {
        std::string byte = hex.substr(i, 2);
        result[i / 2] = static_cast<uint8_t>(std::stoi(byte, nullptr, 16));
    }
    
    return result;
}

std::string Encryption::random_string(size_t len) {
    static const char charset[] = 
        "0123456789"
        "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        "abcdefghijklmnopqrstuvwxyz";
    
    std::vector<uint8_t> random = random_bytes(len);
    std::string result(len, 0);
    
    for (size_t i = 0; i < len; ++i) {
        result[i] = charset[random[i] % (sizeof(charset) - 1)];
    }
    
    return result;
}

std::vector<uint8_t> Encryption::compute_dh_shared_key(const DHParams& params, 
                                                     const std::vector<uint8_t>& private_key) {
    std::vector<uint8_t> shared_key;
    
    // 创建DH上下文
    DH* dh = DH_new();
    if (!dh) {
        return shared_key;
    }
    
    // 设置参数
    BIGNUM* p = BN_bin2bn(params.p.data(), params.p.size(), nullptr);
    BIGNUM* g = BN_bin2bn(params.g.data(), params.g.size(), nullptr);
    BIGNUM* priv = BN_bin2bn(private_key.data(), private_key.size(), nullptr);
    
    if (!p || !g || !priv) {
        if (p) BN_free(p);
        if (g) BN_free(g);
        if (priv) BN_free(priv);
        DH_free(dh);
        return shared_key;
    }
    
    // 设置DH参数
    if (DH_set0_pqg(dh, p, nullptr, g) != 1) {
        BN_free(p);
        BN_free(g);
        BN_free(priv);
        DH_free(dh);
        return shared_key;
    }
    
    // 设置私钥
    BIGNUM* pub = BN_new();
    if (!pub) {
        BN_free(priv);
        DH_free(dh);
        return shared_key;
    }
    
    if (DH_set0_key(dh, pub, priv) != 1) {
        BN_free(pub);
        BN_free(priv);
        DH_free(dh);
        return shared_key;
    }
    
    // 转换对方公钥
    BIGNUM* peer_pub_key = BN_bin2bn(params.public_key.data(), 
                                     params.public_key.size(), nullptr);
    if (!peer_pub_key) {
        DH_free(dh);
        return shared_key;
    }
    
    // 计算共享密钥
    shared_key.resize(DH_size(dh));
    int key_size = DH_compute_key(shared_key.data(), peer_pub_key, dh);
    
    if (key_size <= 0) {
        shared_key.clear();
    } else {
        shared_key.resize(key_size);
    }
    
    // 清理
    BN_free(peer_pub_key);
    DH_free(dh);
    
    return shared_key;
}

void Encryption::derive_key_and_iv(const std::vector<uint8_t>& shared_key, 
                                 std::vector<uint8_t>& key, 
                                 std::vector<uint8_t>& iv) {
    // 设置派生密钥的大小
    const size_t key_size = 32;  // AES-256
    const size_t iv_size = 16;   // AES-CBC IV
    
    // 使用HKDF派生密钥和IV
    std::vector<uint8_t> derived(key_size + iv_size);
    
    // 使用EVP_PKEY_CTX进行HKDF
    EVP_PKEY_CTX* pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, nullptr);
    if (!pctx) {
        return;
    }
    
    // 初始化HKDF
    if (EVP_PKEY_derive_init(pctx) <= 0) {
        EVP_PKEY_CTX_free(pctx);
        return;
    }
    
    // 设置派生算法
    if (EVP_PKEY_CTX_set_hkdf_md(pctx, EVP_sha256()) <= 0) {
        EVP_PKEY_CTX_free(pctx);
        return;
    }
    
    // 设置输入密钥
    if (EVP_PKEY_CTX_set1_hkdf_key(pctx, shared_key.data(), shared_key.size()) <= 0) {
        EVP_PKEY_CTX_free(pctx);
        return;
    }
    
    // 设置salt（这里使用固定salt，可以根据需要调整）
    const unsigned char* salt = (const unsigned char*)"FileTrasferSalt";
    if (EVP_PKEY_CTX_set1_hkdf_salt(pctx, salt, strlen((const char*)salt)) <= 0) {
        EVP_PKEY_CTX_free(pctx);
        return;
    }
    
    // 设置info（这里使用固定info，可以根据需要调整）
    const unsigned char* info = (const unsigned char*)"AES-256-CBC-Key-IV";
    if (EVP_PKEY_CTX_add1_hkdf_info(pctx, info, strlen((const char*)info)) <= 0) {
        EVP_PKEY_CTX_free(pctx);
        return;
    }
    
    // 派生密钥和IV
    size_t derived_len = derived.size();
    if (EVP_PKEY_derive(pctx, derived.data(), &derived_len) <= 0) {
        EVP_PKEY_CTX_free(pctx);
        return;
    }
    
    // 调整输出大小
    derived.resize(derived_len);
    
    // 清理
    EVP_PKEY_CTX_free(pctx);
    
    // 分离密钥和IV
    key = std::vector<uint8_t>(derived.begin(), derived.begin() + key_size);
    iv = std::vector<uint8_t>(derived.begin() + key_size, derived.begin() + key_size + iv_size);
}

} // namespace utils
} // namespace ft 