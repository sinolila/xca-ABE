#include "sm9_bridge.h"
#include <string.h>
#include <stdlib.h>
#include <gmssl/sm9.h>
#include <gmssl/error.h>

// 封装EVP_PKEY结构体中的SM9密钥
// 这里需要根据实际的EVP_PKEY结构和GmSSL的SM9实现进行适配

// 创建一个新的EVP_PKEY对象，包含SM9签名主密钥
EVP_PKEY *EVP_PKEY_new_SM9_SIGN_MASTER_KEY(const SM9_SIGN_MASTER_KEY *msk)
{
    EVP_PKEY *pkey = EVP_PKEY_new();
    if (!pkey)
        return NULL;
        
    // 分配SM9_SIGN_MASTER_KEY内存并复制
    SM9_SIGN_MASTER_KEY *key_copy = malloc(sizeof(SM9_SIGN_MASTER_KEY));
    if (!key_copy) {
        EVP_PKEY_free(pkey);
        return NULL;
    }
    
    // 复制SM9密钥数据
    memcpy(key_copy, msk, sizeof(SM9_SIGN_MASTER_KEY));
    
    // 设置类型和密钥数据
    if (!EVP_PKEY_assign(pkey, EVP_PKEY_SM9_SIGN, key_copy)) {
        free(key_copy);
        EVP_PKEY_free(pkey);
        return NULL;
    }
    
    return pkey;
}

// 其他类似的函数，如EVP_PKEY_new_SM9_ENC_MASTER_KEY等...

// 从EVP_PKEY中获取SM9签名主密钥
int EVP_PKEY_get_SM9_SIGN_MASTER_KEY(EVP_PKEY *pkey, SM9_SIGN_MASTER_KEY *msk)
{
    if (!pkey || !msk || EVP_PKEY_id(pkey) != EVP_PKEY_SM9_SIGN)
        return 0;
        
    // 从EVP_PKEY中获取SM9_SIGN_MASTER_KEY指针
    SM9_SIGN_MASTER_KEY *key_data = EVP_PKEY_get0(pkey);
    if (!key_data)
        return 0;
        
    // 复制数据
    memcpy(msk, key_data, sizeof(SM9_SIGN_MASTER_KEY));
    return 1;
}

// 其他类似的函数，如EVP_PKEY_get_SM9_ENC_MASTER_KEY等...

// 生成SM9签名主密钥并返回EVP_PKEY
EVP_PKEY *SM9_SIGN_MASTER_KEY_generate_key(void)
{
    SM9_SIGN_MASTER_KEY msk;
    
    if (sm9_sign_master_key_generate(&msk) != 1)
        return NULL;
        
    EVP_PKEY *pkey = EVP_PKEY_new_SM9_SIGN_MASTER_KEY(&msk);
    
    // 清除敏感数据
    memset(&msk, 0, sizeof(msk));
    
    return pkey;
}

// 其他生成函数...

// 从SM9签名主密钥提取用户密钥
int SM9_extract_sign_key(EVP_PKEY *master_key, const char *id, size_t idlen, EVP_PKEY **user_key)
{
    if (!master_key || !id || !user_key || EVP_PKEY_id(master_key) != EVP_PKEY_SM9_SIGN)
        return 0;
        
    // 获取主密钥
    SM9_SIGN_MASTER_KEY msk;
    if (!EVP_PKEY_get_SM9_SIGN_MASTER_KEY(master_key, &msk))
        return 0;
        
    // 提取用户密钥
    SM9_SIGN_KEY key;
    if (sm9_sign_master_key_extract_key(&msk, id, idlen, &key) != 1)
        return 0;
        
    // 创建新的EVP_PKEY
    *user_key = EVP_PKEY_new_SM9_SIGN_KEY(&key);
    
    // 清除敏感数据
    memset(&key, 0, sizeof(key));
    memset(&msk, 0, sizeof(msk));
    
    return *user_key ? 1 : 0;
}

// 其他提取函数...