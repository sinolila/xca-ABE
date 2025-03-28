/*
 * SM9 Bridge - 连接GmSSL的SM9和XCA的EVP_PKEY接口
 */

#ifndef _SM9_BRIDGE_H
#define _SM9_BRIDGE_H

#include <gmssl/sm9.h>
#include <openssl/evp.h>

/* 定义EVP_PKEY_SM9类型常量（如果OpenSSL未定义） */
#ifndef EVP_PKEY_SM9_SIGN
#define EVP_PKEY_SM9_SIGN 406
#endif

#ifndef EVP_PKEY_SM9_ENC
#define EVP_PKEY_SM9_ENC 407
#endif

namespace sm9_bridge {

/* SM9签名主密钥转换为EVP_PKEY */
EVP_PKEY *sign_master_key_to_pkey(const SM9_SIGN_MASTER_KEY *msk, bool public_only = false);

/* SM9加密主密钥转换为EVP_PKEY */
EVP_PKEY *enc_master_key_to_pkey(const SM9_ENC_MASTER_KEY *msk, bool public_only = false);

/* SM9签名私钥转换为EVP_PKEY */
EVP_PKEY *sign_key_to_pkey(const SM9_SIGN_KEY *key);

/* SM9加密私钥转换为EVP_PKEY */
EVP_PKEY *enc_key_to_pkey(const SM9_ENC_KEY *key);

/* 从EVP_PKEY提取SM9签名主密钥 */
bool sign_master_key_from_pkey(SM9_SIGN_MASTER_KEY *msk, const EVP_PKEY *pkey);

/* 从EVP_PKEY提取SM9加密主密钥 */
bool enc_master_key_from_pkey(SM9_ENC_MASTER_KEY *msk, const EVP_PKEY *pkey);

/* 从EVP_PKEY提取SM9签名私钥 */
bool sign_key_from_pkey(SM9_SIGN_KEY *key, const EVP_PKEY *pkey);

/* 从EVP_PKEY提取SM9加密私钥 */
bool enc_key_from_pkey(SM9_ENC_KEY *key, const EVP_PKEY *pkey);

/* 初始化SM9桥接层 */
bool initialize();

/* 导出SM9公钥为DER格式 */
bool sign_master_public_key_to_der(const EVP_PKEY *pkey, unsigned char **out, size_t *outlen);
bool enc_master_public_key_to_der(const EVP_PKEY *pkey, unsigned char **out, size_t *outlen);

/* 从DER格式创建SM9公钥EVP_PKEY */
EVP_PKEY *sign_master_public_key_from_der(const unsigned char *der, size_t derlen);
EVP_PKEY *enc_master_public_key_from_der(const unsigned char *der, size_t derlen);

/* 清理分配的内存 */
void free_der_data(unsigned char *data);

} // namespace sm9_bridge

#endif // XCA_SM9_BRIDGE_H