#include <gtest/gtest.h>
#include "../../src/common/utils/crypto/encryption.h"
#include "../../src/common/protocol/messages/key_exchange_message.h"
#include <string>
#include <iostream>

namespace ft {
namespace test {

// 测试DH密钥交换功能
TEST(EncryptionTest, DHKeyExchange) {
    // 1. 生成客户端DH参数和密钥对
    std::vector<uint8_t> client_private_key;
    utils::DHParams client_params = utils::Encryption::generate_dh_params(client_private_key);
    
    // 验证生成的参数不为空
    ASSERT_FALSE(client_params.p.empty());
    ASSERT_FALSE(client_params.g.empty());
    ASSERT_FALSE(client_params.public_key.empty());
    ASSERT_FALSE(client_private_key.empty());
    
    // 2. 生成服务器DH参数和密钥对 (使用相同的p和g参数)
    std::vector<uint8_t> server_private_key;
    utils::DHParams server_params = utils::Encryption::generate_dh_params(server_private_key);
    
    // 验证服务器参数也不为空
    ASSERT_FALSE(server_params.p.empty());
    ASSERT_FALSE(server_params.g.empty());
    ASSERT_FALSE(server_params.public_key.empty());
    ASSERT_FALSE(server_private_key.empty());
    
    // 3. 客户端和服务器分别计算共享密钥
    // 注意：在实际应用中，客户端使用服务器的公钥，服务器使用客户端的公钥
    utils::DHParams client_to_server_params;
    client_to_server_params.p = client_params.p;
    client_to_server_params.g = client_params.g;
    client_to_server_params.public_key = server_params.public_key; // 客户端使用服务器公钥
    
    utils::DHParams server_to_client_params;
    server_to_client_params.p = server_params.p;
    server_to_client_params.g = server_params.g;
    server_to_client_params.public_key = client_params.public_key; // 服务器使用客户端公钥
    
    std::vector<uint8_t> client_shared_key = utils::Encryption::compute_dh_shared_key(
        client_to_server_params, client_private_key);
    
    std::vector<uint8_t> server_shared_key = utils::Encryption::compute_dh_shared_key(
        server_to_client_params, server_private_key);
    
    // 验证共享密钥不为空
    ASSERT_FALSE(client_shared_key.empty());
    ASSERT_FALSE(server_shared_key.empty());
    
    // 4. 验证双方计算的共享密钥相同
    ASSERT_EQ(client_shared_key.size(), server_shared_key.size());
    ASSERT_EQ(client_shared_key, server_shared_key);
    
    // 5. 测试从共享密钥派生AES密钥和IV
    std::vector<uint8_t> client_key, client_iv;
    utils::Encryption::derive_key_and_iv(client_shared_key, client_key, client_iv);
    
    std::vector<uint8_t> server_key, server_iv;
    utils::Encryption::derive_key_and_iv(server_shared_key, server_key, server_iv);
    
    // 验证派生的密钥长度正确
    ASSERT_EQ(client_key.size(), 32);  // AES-256 密钥长度
    ASSERT_EQ(client_iv.size(), 16);   // AES-CBC IV长度
    
    // 验证双方派生的密钥和IV相同
    ASSERT_EQ(client_key, server_key);
    ASSERT_EQ(client_iv, server_iv);
}

// 测试AES加密和解密功能
TEST(EncryptionTest, AESEncryptDecrypt) {
    // 1. 生成随机密钥和IV
    std::vector<uint8_t> key = utils::Encryption::random_bytes(32); // AES-256
    std::vector<uint8_t> iv = utils::Encryption::random_bytes(16);  // AES-CBC IV
    
    // 2. 准备测试数据
    const std::string test_cases[] = {
        "",  // 空字符串
        "Hello, World!",  // 短字符串
        std::string(1024, 'A'),  // 1KB的数据
        std::string(1024 * 10, 'B')  // 10KB的数据
    };
    
    for (const auto& data_str : test_cases) {
        std::vector<uint8_t> plaintext(data_str.begin(), data_str.end());
        
        // 3. 加密数据
        std::vector<uint8_t> ciphertext = utils::Encryption::aes_encrypt(plaintext, key, iv);
        
        // 空数据的情况
        if (plaintext.empty()) {
            ASSERT_TRUE(ciphertext.empty());
            continue;
        }
        
        // 验证加密后的数据不为空且与原始数据不同
        ASSERT_FALSE(ciphertext.empty());
        ASSERT_NE(ciphertext, plaintext);
        
        // 4. 解密数据
        std::vector<uint8_t> decrypted = utils::Encryption::aes_decrypt(ciphertext, key, iv);
        
        // 验证解密后的数据与原始数据相同
        ASSERT_EQ(decrypted, plaintext);
    }
}

// 测试密钥交换消息序列化和反序列化
TEST(EncryptionTest, KeyExchangeMessageSerialization) {
    // 1. 创建密钥交换消息
    protocol::KeyExchangeMessage msg(protocol::KeyExchangePhase::CLIENT_HELLO);
    
    // 2. 设置随机参数
    std::vector<uint8_t> params = utils::Encryption::random_bytes(128);
    msg.set_exchange_params(params);
    
    // 3. 编码消息
    std::vector<uint8_t> encoded;
    ASSERT_TRUE(msg.encode(encoded));
    ASSERT_FALSE(encoded.empty());
    
    // 4. 解码消息
    protocol::Message base_msg;
    ASSERT_TRUE(base_msg.decode(encoded));
    
    // 5. 转换回密钥交换消息并验证
    protocol::KeyExchangeMessage decoded_msg(base_msg);
    ASSERT_EQ(decoded_msg.get_operation_type(), protocol::OperationType::KEY_EXCHANGE);
    ASSERT_EQ(decoded_msg.get_exchange_phase(), protocol::KeyExchangePhase::CLIENT_HELLO);
    ASSERT_EQ(decoded_msg.get_exchange_params(), params);
}

} // namespace test
} // namespace ft 