#include "sm9_bridge.h"
#include <string.h>
#include <stdlib.h>
#include <gmssl/sm9.h>
#include <gmssl/error.h>

// ��װEVP_PKEY�ṹ���е�SM9��Կ
// ������Ҫ����ʵ�ʵ�EVP_PKEY�ṹ��GmSSL��SM9ʵ�ֽ�������

// ����һ���µ�EVP_PKEY���󣬰���SM9ǩ������Կ
EVP_PKEY *EVP_PKEY_new_SM9_SIGN_MASTER_KEY(const SM9_SIGN_MASTER_KEY *msk)
{
    EVP_PKEY *pkey = EVP_PKEY_new();
    if (!pkey)
        return NULL;
        
    // ����SM9_SIGN_MASTER_KEY�ڴ沢����
    SM9_SIGN_MASTER_KEY *key_copy = malloc(sizeof(SM9_SIGN_MASTER_KEY));
    if (!key_copy) {
        EVP_PKEY_free(pkey);
        return NULL;
    }
    
    // ����SM9��Կ����
    memcpy(key_copy, msk, sizeof(SM9_SIGN_MASTER_KEY));
    
    // �������ͺ���Կ����
    if (!EVP_PKEY_assign(pkey, EVP_PKEY_SM9_SIGN, key_copy)) {
        free(key_copy);
        EVP_PKEY_free(pkey);
        return NULL;
    }
    
    return pkey;
}

// �������Ƶĺ�������EVP_PKEY_new_SM9_ENC_MASTER_KEY��...

// ��EVP_PKEY�л�ȡSM9ǩ������Կ
int EVP_PKEY_get_SM9_SIGN_MASTER_KEY(EVP_PKEY *pkey, SM9_SIGN_MASTER_KEY *msk)
{
    if (!pkey || !msk || EVP_PKEY_id(pkey) != EVP_PKEY_SM9_SIGN)
        return 0;
        
    // ��EVP_PKEY�л�ȡSM9_SIGN_MASTER_KEYָ��
    SM9_SIGN_MASTER_KEY *key_data = EVP_PKEY_get0(pkey);
    if (!key_data)
        return 0;
        
    // ��������
    memcpy(msk, key_data, sizeof(SM9_SIGN_MASTER_KEY));
    return 1;
}

// �������Ƶĺ�������EVP_PKEY_get_SM9_ENC_MASTER_KEY��...

// ����SM9ǩ������Կ������EVP_PKEY
EVP_PKEY *SM9_SIGN_MASTER_KEY_generate_key(void)
{
    SM9_SIGN_MASTER_KEY msk;
    
    if (sm9_sign_master_key_generate(&msk) != 1)
        return NULL;
        
    EVP_PKEY *pkey = EVP_PKEY_new_SM9_SIGN_MASTER_KEY(&msk);
    
    // �����������
    memset(&msk, 0, sizeof(msk));
    
    return pkey;
}

// �������ɺ���...

// ��SM9ǩ������Կ��ȡ�û���Կ
int SM9_extract_sign_key(EVP_PKEY *master_key, const char *id, size_t idlen, EVP_PKEY **user_key)
{
    if (!master_key || !id || !user_key || EVP_PKEY_id(master_key) != EVP_PKEY_SM9_SIGN)
        return 0;
        
    // ��ȡ����Կ
    SM9_SIGN_MASTER_KEY msk;
    if (!EVP_PKEY_get_SM9_SIGN_MASTER_KEY(master_key, &msk))
        return 0;
        
    // ��ȡ�û���Կ
    SM9_SIGN_KEY key;
    if (sm9_sign_master_key_extract_key(&msk, id, idlen, &key) != 1)
        return 0;
        
    // �����µ�EVP_PKEY
    *user_key = EVP_PKEY_new_SM9_SIGN_KEY(&key);
    
    // �����������
    memset(&key, 0, sizeof(key));
    memset(&msk, 0, sizeof(msk));
    
    return *user_key ? 1 : 0;
}

// ������ȡ����...