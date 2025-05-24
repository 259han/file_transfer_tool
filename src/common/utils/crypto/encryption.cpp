#include "encryption.h"
#include <openssl/md5.h>
#include <openssl/sha.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/aes.h>
#include <openssl/param_build.h>
#include <openssl/core_names.h>
#include <openssl/bn.h>
#include <openssl/kdf.h>
#include <sstream>
#include <iomanip>
#include <cstring>
#include <random>

namespace ft {
namespace utils {

/**
 * @brief 使用新的EVP API和RFC 7919命名组创建DH密钥对
 * 
 * 使用OpenSSL 3.0的EVP API和预定义的安全组"ffdhe2048"来生成DH密钥对。
 * 这种方法避免了使用已废弃的DH_*函数，并且使用了标准化的安全参数。
 * 
 * @param private_key [输出] 私钥
 * @return DH参数结构体，包含p、g和公钥
 */
static DHParams create_dh_params_from_predefined(std::vector<uint8_t>& private_key) {
    DHParams params;
    
    // 使用EVP_PKEY_CTX创建DH密钥对
    EVP_PKEY_CTX* pctx = nullptr;
    EVP_PKEY* pkey = nullptr;
    
    do {
        // 创建DH密钥生成上下文
        pctx = EVP_PKEY_CTX_new_from_name(nullptr, "DH", nullptr);
        if (!pctx) break;
        
        // 初始化密钥生成
        if (EVP_PKEY_keygen_init(pctx) <= 0) break;
        
        // 使用预定义的安全组 ffdhe2048 (RFC 7919)
        OSSL_PARAM param_array[2];
        param_array[0] = OSSL_PARAM_construct_utf8_string("group", (char*)"ffdhe2048", 0);
        param_array[1] = OSSL_PARAM_construct_end();
        
        // 设置DH参数
        if (EVP_PKEY_CTX_set_params(pctx, param_array) <= 0) break;
        
        // 生成密钥对
        if (EVP_PKEY_generate(pctx, &pkey) <= 0) break;
        
        // 获取生成的密钥参数
        BIGNUM* p_bn = nullptr;
        BIGNUM* g_bn = nullptr;
        BIGNUM* priv_bn = nullptr;
        BIGNUM* pub_bn = nullptr;
        
        if (!EVP_PKEY_get_bn_param(pkey, OSSL_PKEY_PARAM_FFC_P, &p_bn) ||
            !EVP_PKEY_get_bn_param(pkey, OSSL_PKEY_PARAM_FFC_G, &g_bn) ||
            !EVP_PKEY_get_bn_param(pkey, OSSL_PKEY_PARAM_PRIV_KEY, &priv_bn) ||
            !EVP_PKEY_get_bn_param(pkey, OSSL_PKEY_PARAM_PUB_KEY, &pub_bn)) {
            if (p_bn) BN_free(p_bn);
            if (g_bn) BN_free(g_bn);
            if (priv_bn) BN_free(priv_bn);
            if (pub_bn) BN_free(pub_bn);
            break;
        }
        
        // 将密钥转换为字节数组
        params.p.resize(BN_num_bytes(p_bn));
        BN_bn2bin(p_bn, params.p.data());
        
        params.g.resize(BN_num_bytes(g_bn));
        BN_bn2bin(g_bn, params.g.data());
        
        params.public_key.resize(BN_num_bytes(pub_bn));
        BN_bn2bin(pub_bn, params.public_key.data());
        
        private_key.resize(BN_num_bytes(priv_bn));
        BN_bn2bin(priv_bn, private_key.data());
        
        // 清理BIGNUM
        BN_free(p_bn);
        BN_free(g_bn);
        BN_free(priv_bn);
        BN_free(pub_bn);
        
    } while (false);
    
    // 清理资源
    if (pctx) EVP_PKEY_CTX_free(pctx);
    if (pkey) EVP_PKEY_free(pkey);
    
    return params;
}

// 修改原有的generate_dh_params方法，使用预计算的参数
DHParams Encryption::generate_dh_params(std::vector<uint8_t>& private_key) {
    // 使用预定义参数更快速地创建密钥对，而不是每次生成新的DH参数
    return create_dh_params_from_predefined(private_key);
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
    
    // 使用EVP API进行DH密钥交换
    EVP_PKEY_CTX* pctx = nullptr;
    EVP_PKEY* pkey = nullptr;
    EVP_PKEY* peer_key = nullptr;
    OSSL_PARAM_BLD* param_bld = nullptr;
    OSSL_PARAM* param = nullptr;
    OSSL_PARAM_BLD* peer_param_bld = nullptr;
    OSSL_PARAM* peer_param = nullptr;
    
    do {
        // 创建本地密钥的参数构建器
        param_bld = OSSL_PARAM_BLD_new();
        if (!param_bld) break;
        
        // 设置DH参数
        BIGNUM* p_bn = BN_bin2bn(params.p.data(), params.p.size(), nullptr);
        BIGNUM* g_bn = BN_bin2bn(params.g.data(), params.g.size(), nullptr);
        BIGNUM* priv_bn = BN_bin2bn(private_key.data(), private_key.size(), nullptr);
        
        if (!p_bn || !g_bn || !priv_bn) {
            if (p_bn) BN_free(p_bn);
            if (g_bn) BN_free(g_bn);
            if (priv_bn) BN_free(priv_bn);
            break;
        }
        
        if (!OSSL_PARAM_BLD_push_BN(param_bld, OSSL_PKEY_PARAM_FFC_P, p_bn) ||
            !OSSL_PARAM_BLD_push_BN(param_bld, OSSL_PKEY_PARAM_FFC_G, g_bn) ||
            !OSSL_PARAM_BLD_push_BN(param_bld, OSSL_PKEY_PARAM_PRIV_KEY, priv_bn)) {
            BN_free(p_bn);
            BN_free(g_bn);
            BN_free(priv_bn);
            break;
        }
        
        // 构建本地密钥参数
        param = OSSL_PARAM_BLD_to_param(param_bld);
        if (!param) {
            BN_free(p_bn);
            BN_free(g_bn);
            BN_free(priv_bn);
            break;
        }
        
        // 创建本地密钥
        EVP_PKEY_CTX* key_ctx = EVP_PKEY_CTX_new_from_name(nullptr, "DH", nullptr);
        if (!key_ctx) {
            BN_free(p_bn);
            BN_free(g_bn);
            BN_free(priv_bn);
            break;
        }
        
        if (EVP_PKEY_fromdata_init(key_ctx) <= 0 ||
            EVP_PKEY_fromdata(key_ctx, &pkey, EVP_PKEY_KEYPAIR, param) <= 0) {
            EVP_PKEY_CTX_free(key_ctx);
            BN_free(p_bn);
            BN_free(g_bn);
            BN_free(priv_bn);
            break;
        }
        EVP_PKEY_CTX_free(key_ctx);
        
        // 创建对方公钥的参数构建器
        peer_param_bld = OSSL_PARAM_BLD_new();
        if (!peer_param_bld) {
            BN_free(p_bn);
            BN_free(g_bn);
            BN_free(priv_bn);
            break;
        }
        
        BIGNUM* peer_pub_bn = BN_bin2bn(params.public_key.data(), params.public_key.size(), nullptr);
        if (!peer_pub_bn) {
            BN_free(p_bn);
            BN_free(g_bn);
            BN_free(priv_bn);
            break;
        }
        
        if (!OSSL_PARAM_BLD_push_BN(peer_param_bld, OSSL_PKEY_PARAM_FFC_P, p_bn) ||
            !OSSL_PARAM_BLD_push_BN(peer_param_bld, OSSL_PKEY_PARAM_FFC_G, g_bn) ||
            !OSSL_PARAM_BLD_push_BN(peer_param_bld, OSSL_PKEY_PARAM_PUB_KEY, peer_pub_bn)) {
            BN_free(p_bn);
            BN_free(g_bn);
            BN_free(priv_bn);
            BN_free(peer_pub_bn);
            break;
        }
        
        // 构建对方公钥参数
        peer_param = OSSL_PARAM_BLD_to_param(peer_param_bld);
        if (!peer_param) {
            BN_free(p_bn);
            BN_free(g_bn);
            BN_free(priv_bn);
            BN_free(peer_pub_bn);
            break;
        }
        
        // 创建对方公钥
        EVP_PKEY_CTX* peer_key_ctx = EVP_PKEY_CTX_new_from_name(nullptr, "DH", nullptr);
        if (!peer_key_ctx) {
            BN_free(p_bn);
            BN_free(g_bn);
            BN_free(priv_bn);
            BN_free(peer_pub_bn);
            break;
        }
        
        if (EVP_PKEY_fromdata_init(peer_key_ctx) <= 0 ||
            EVP_PKEY_fromdata(peer_key_ctx, &peer_key, EVP_PKEY_PUBLIC_KEY, peer_param) <= 0) {
            EVP_PKEY_CTX_free(peer_key_ctx);
            BN_free(p_bn);
            BN_free(g_bn);
            BN_free(priv_bn);
            BN_free(peer_pub_bn);
            break;
        }
        EVP_PKEY_CTX_free(peer_key_ctx);
        
        // 清理BIGNUM
        BN_free(p_bn);
        BN_free(g_bn);
        BN_free(priv_bn);
        BN_free(peer_pub_bn);
        
        // 创建密钥交换上下文
        pctx = EVP_PKEY_CTX_new(pkey, nullptr);
        if (!pctx) break;
        
        // 初始化密钥交换
        if (EVP_PKEY_derive_init(pctx) <= 0) break;
        
        // 设置对方公钥
        if (EVP_PKEY_derive_set_peer(pctx, peer_key) <= 0) break;
        
        // 获取共享密钥长度
        size_t shared_key_len = 0;
        if (EVP_PKEY_derive(pctx, nullptr, &shared_key_len) <= 0) break;
        
        // 计算共享密钥
        shared_key.resize(shared_key_len);
        if (EVP_PKEY_derive(pctx, shared_key.data(), &shared_key_len) <= 0) {
            shared_key.clear();
            break;
        }
        
        shared_key.resize(shared_key_len);
        
    } while (false);
    
    // 清理资源
    if (peer_param) OSSL_PARAM_free(peer_param);
    if (peer_param_bld) OSSL_PARAM_BLD_free(peer_param_bld);
    if (param) OSSL_PARAM_free(param);
    if (param_bld) OSSL_PARAM_BLD_free(param_bld);
    if (pctx) EVP_PKEY_CTX_free(pctx);
    if (pkey) EVP_PKEY_free(pkey);
    if (peer_key) EVP_PKEY_free(peer_key);
    
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