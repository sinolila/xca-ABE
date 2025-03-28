#ifndef SM9_BRIDGE_H
#define SM9_BRIDGE_H

#include <openssl/evp.h>
#include <gmssl/sm9.h>

#ifdef __cplusplus
extern "C" {
#endif

// EVP_PKEY��SM9֮����ŽӺ���
EVP_PKEY *EVP_PKEY_new_SM9_SIGN_MASTER_KEY(const SM9_SIGN_MASTER_KEY *msk);
EVP_PKEY *EVP_PKEY_new_SM9_ENC_MASTER_KEY(const SM9_ENC_MASTER_KEY *msk);
EVP_PKEY *EVP_PKEY_new_SM9_SIGN_KEY(const SM9_SIGN_KEY *key);
EVP_PKEY *EVP_PKEY_new_SM9_ENC_KEY(const SM9_ENC_KEY *key);

int EVP_PKEY_get_SM9_SIGN_MASTER_KEY(EVP_PKEY *pkey, SM9_SIGN_MASTER_KEY *msk);
int EVP_PKEY_get_SM9_ENC_MASTER_KEY(EVP_PKEY *pkey, SM9_ENC_MASTER_KEY *msk);
int EVP_PKEY_get_SM9_SIGN_KEY(EVP_PKEY *pkey, SM9_SIGN_KEY *key);
int EVP_PKEY_get_SM9_ENC_KEY(EVP_PKEY *pkey, SM9_ENC_KEY *key);

// SM9��Կ���ɺ����ķ�װ
EVP_PKEY *SM9_SIGN_MASTER_KEY_generate_key(void);
EVP_PKEY *SM9_ENC_MASTER_KEY_generate_key(void);

// ��SM9����Կ����ȡ�û���Կ
int SM9_extract_sign_key(EVP_PKEY *master_key, const char *id, size_t idlen, EVP_PKEY **user_key);
int SM9_extract_enc_key(EVP_PKEY *master_key, const char *id, size_t idlen, EVP_PKEY **user_key);

#ifdef __cplusplus
}
#endif

#endif /* SM9_BRIDGE_H */