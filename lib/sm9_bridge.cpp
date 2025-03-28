#include "sm9_bridge.h"
#include <gmssl/error.h>
#include <openssl/err.h>
#include <cstring>

/* SM9密钥数据存储在EVP_PKEY中的结构 */
struct SM9KeyData {
    int key_type; /* 1:签名主密钥, 2:加密主密钥, 3:签名私钥, 4:加密私钥 */
    bool is_public_only; /* 是否只包含公钥 */
    union {
        SM9_SIGN_MASTER_KEY sign_master;
        SM9_ENC_MASTER_KEY enc_master;
        SM9_SIGN_KEY sign_key;
        SM9_ENC_KEY enc_key;
    } u;
};

/* 为SM9注册到OpenSSL的回调函数 */
static void sm9_key_data_free(void *ptr) 
{
    if (ptr) {
        SM9KeyData *data = static_cast<SM9KeyData*>(ptr);
        delete data;
    }
}

namespace sm9_bridge {

/* 创建包装SM9密钥的EVP_PKEY */
static EVP_PKEY* create_pkey_with_sm9_data(int key_type, SM9KeyData* data) 
{
    EVP_PKEY *pkey = EVP_PKEY_new();
    if (!pkey) {
        delete data;
        return nullptr;
    }

    /* 根据密钥类型设置正确的NID */
    int nid = (key_type == 1 || key_type == 3) ? EVP_PKEY_SM9_SIGN : EVP_PKEY_SM9_ENC;

    /* 设置自定义清理函数 */
    if (!EVP_PKEY_set_type(pkey, nid) || 
        !EVP_PKEY_assign(pkey, nid, data)) {
        EVP_PKEY_free(pkey);
        delete data;
        return nullptr;
    }

    return pkey;
}

EVP_PKEY *sign_master_key_to_pkey(const SM9_SIGN_MASTER_KEY *msk, bool public_only)
{
    if (!msk) return nullptr;
    
    SM9KeyData *data = new SM9KeyData();
    if (!data) return nullptr;
    
    data->key_type = 1; /* 签名主密钥 */
    data->is_public_only = public_only;
    
    /* 复制SM9签名主密钥 */
    memcpy(&data->u.sign_master, msk, sizeof(SM9_SIGN_MASTER_KEY));
    
    /* 如果只需要公钥部分，清除私钥数据 */
    if (public_only) {
        memset(&data->u.sign_master.ks, 0, sizeof(sm9_z256_t));
    }
    
    return create_pkey_with_sm9_data(1, data);
}

EVP_PKEY *enc_master_key_to_pkey(const SM9_ENC_MASTER_KEY *msk, bool public_only)
{
    if (!msk) return nullptr;
    
    SM9KeyData *data = new SM9KeyData();
    if (!data) return nullptr;
    
    data->key_type = 2; /* 加密主密钥 */
    data->is_public_only = public_only;
    
    /* 复制SM9加密主密钥 */
    memcpy(&data->u.enc_master, msk, sizeof(SM9_ENC_MASTER_KEY));
    
    /* 如果只需要公钥部分，清除私钥数据 */
    if (public_only) {
        memset(&data->u.enc_master.ke, 0, sizeof(sm9_z256_t));
    }
    
    return create_pkey_with_sm9_data(2, data);
}

EVP_PKEY *sign_key_to_pkey(const SM9_SIGN_KEY *key)
{
    if (!key) return nullptr;
    
    SM9KeyData *data = new SM9KeyData();
    if (!data) return nullptr;
    
    data->key_type = 3; /* 签名私钥 */
    data->is_public_only = false;
    
    /* 复制SM9签名私钥 */
    memcpy(&data->u.sign_key, key, sizeof(SM9_SIGN_KEY));
    
    return create_pkey_with_sm9_data(3, data);
}

EVP_PKEY *enc_key_to_pkey(const SM9_ENC_KEY *key)
{
    if (!key) return nullptr;
    
    SM9KeyData *data = new SM9KeyData();
    if (!data) return nullptr;
    
    data->key_type = 4; /* 加密私钥 */
    data->is_public_only = false;
    
    /* 复制SM9加密私钥 */
    memcpy(&data->u.enc_key, key, sizeof(SM9_ENC_KEY));
    
    return create_pkey_with_sm9_data(4, data);
}

/* 检查EVP_PKEY是否为SM9类型并提取数据 */
static SM9KeyData* get_sm9_key_data(const EVP_PKEY *pkey, int expected_type)
{
    if (!pkey) return nullptr;
    
    int type = EVP_PKEY_id(pkey);
    if (type != EVP_PKEY_SM9_SIGN && type != EVP_PKEY_SM9_ENC) {
        return nullptr;
    }
    
    SM9KeyData *data = static_cast<SM9KeyData*>(EVP_PKEY_get0(pkey));
    if (!data || data->key_type != expected_type) {
        return nullptr;
    }
    
    return data;
}

bool sign_master_key_from_pkey(SM9_SIGN_MASTER_KEY *msk, const EVP_PKEY *pkey)
{
    if (!msk) return false;
    
    SM9KeyData *data = get_sm9_key_data(pkey, 1);
    if (!data) return false;
    
    memcpy(msk, &data->u.sign_master, sizeof(SM9_SIGN_MASTER_KEY));
    return true;
}

bool enc_master_key_from_pkey(SM9_ENC_MASTER_KEY *msk, const EVP_PKEY *pkey)
{
    if (!msk) return false;
    
    SM9KeyData *data = get_sm9_key_data(pkey, 2);
    if (!data) return false;
    
    memcpy(msk, &data->u.enc_master, sizeof(SM9_ENC_MASTER_KEY));
    return true;
}

bool sign_key_from_pkey(SM9_SIGN_KEY *key, const EVP_PKEY *pkey)
{
    if (!key) return false;
    
    SM9KeyData *data = get_sm9_key_data(pkey, 3);
    if (!data) return false;
    
    memcpy(key, &data->u.sign_key, sizeof(SM9_SIGN_KEY));
    return true;
}

bool enc_key_from_pkey(SM9_ENC_KEY *key, const EVP_PKEY *pkey)
{
    if (!key) return false;
    
    SM9KeyData *data = get_sm9_key_data(pkey, 4);
    if (!data) return false;
    
    memcpy(key, &data->u.enc_key, sizeof(SM9_ENC_KEY));
    return true;
}

bool initialize()
{
    /* 在这里注册EVP_PKEY方法，如果需要的话 */
    /* 在XCA中可能不需要，因为我们只是将GmSSL的结构封装在EVP_PKEY中 */
    return true;
}

bool sign_master_public_key_to_der(const EVP_PKEY *pkey, unsigned char **out, size_t *outlen)
{
    if (!pkey || !out || !outlen) return false;
    
    SM9_SIGN_MASTER_KEY msk;
    if (!sign_master_key_from_pkey(&msk, pkey)) {
        return false;
    }
    
    return sm9_sign_master_public_key_to_der(&msk, out, outlen) == 1;
}

bool enc_master_public_key_to_der(const EVP_PKEY *pkey, unsigned char **out, size_t *outlen)
{
    if (!pkey || !out || !outlen) return false;
    
    SM9_ENC_MASTER_KEY msk;
    if (!enc_master_key_from_pkey(&msk, pkey)) {
        return false;
    }
    
    return sm9_enc_master_public_key_to_der(&msk, out, outlen) == 1;
}

EVP_PKEY *sign_master_public_key_from_der(const unsigned char *der, size_t derlen)
{
    if (!der || derlen == 0) return nullptr;
    
    SM9_SIGN_MASTER_KEY msk;
    const unsigned char *p = der;
    size_t len = derlen;
    
    memset(&msk, 0, sizeof(msk));
    if (sm9_sign_master_public_key_from_der(&msk, &p, &len) != 1) {
        return nullptr;
    }
    
    return sign_master_key_to_pkey(&msk, true);
}

EVP_PKEY *enc_master_public_key_from_der(const unsigned char *der, size_t derlen)
{
    if (!der || derlen == 0) return nullptr;
    
    SM9_ENC_MASTER_KEY msk;
    const unsigned char *p = der;
    size_t len = derlen;
    
    memset(&msk, 0, sizeof(msk));
    if (sm9_enc_master_public_key_from_der(&msk, &p, &len) != 1) {
        return nullptr;
    }
    
    return enc_master_key_to_pkey(&msk, true);
}

void free_der_data(unsigned char *data)
{
    if (data) {
        /* 使用GmSSL提供的内存释放函数，或者直接使用free */
        free(data);
    }
}

} // namespace sm9_bridge 