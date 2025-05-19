#include "protocol_header.h"
#include <openssl/md5.h>
#include <openssl/evp.h>
#include <cstring>

namespace ft {
namespace protocol {

ProtocolHeader::ProtocolHeader(OperationType op, uint8_t flg, uint32_t len)
    : magic(PROTOCOL_MAGIC),
      type(static_cast<uint8_t>(op)),
      flags(flg),
      length(len),
      checksum(0),
      reserved(0) {
    // 我们不再需要重复赋值，因为已经在初始化列表中正确设置了这些值
    // 初始化列表中的值不会丢失
}

uint32_t ProtocolHeader::calculate_checksum(const void* data, size_t len) {
    if (!data || len == 0) {
        return 0;
    }
    
    unsigned char md5_result[MD5_DIGEST_LENGTH];
    
    // 使用 EVP 接口替代直接调用 MD5 函数
    EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
    if (!mdctx) {
        return 0;
    }
    
    if (1 != EVP_DigestInit_ex(mdctx, EVP_md5(), NULL) ||
        1 != EVP_DigestUpdate(mdctx, data, len) ||
        1 != EVP_DigestFinal_ex(mdctx, md5_result, NULL)) {
        EVP_MD_CTX_free(mdctx);
        return 0;
    }
    
    EVP_MD_CTX_free(mdctx);
    
    // 取MD5的前4个字节作为校验和
    uint32_t checksum = 0;
    std::memcpy(&checksum, md5_result, sizeof(uint32_t));
    
    return checksum;
}

} // namespace protocol
} // namespace ft 