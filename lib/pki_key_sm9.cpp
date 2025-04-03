#include "sm9_bridge.h"
#include <openssl/evp.h>
#include <openssl/err.h>
#include <gmssl/error.h>
#include <cstring>
#include <cstdlib>

/* SM9 密钥存储结构 */
struct SM9KeyData {
    int key_type; // 1: 主密钥, 3: 用户密钥
    bool is_public_only;
    union {
        SM9_SIGN_MASTER_KEY sign_master;
        SM9_SIGN_KEY sign_key;
    } u;
};

/* 清理函数 */
static void sm9_key_data_free(void *ptr) {
    if (ptr) {
        SM9KeyData *data = static_cast<SM9KeyData*>(ptr);
        delete data;
    }
}

/* 创建 EVP_PKEY 并封装 SM9KeyData */
static EVP_PKEY* create_pkey_with_sm9_data(int key_type, SM9KeyData* data) {
    EVP_PKEY *pkey = EVP_PKEY_new();
    if (!pkey) {
        delete data;
        return nullptr;
    }

    if (!EVP_PKEY_assign(pkey, EVP_PKEY_SM9_SIGN, data)) {
        EVP_PKEY_free(pkey);
        delete data;
        return nullptr;
    }
    return pkey;
}

namespace sm9_bridge {

/* 生成 SM9 签名主密钥 */
EVP_PKEY *generate_sign_master_key() {
    SM9_SIGN_MASTER_KEY *msk = (SM9_SIGN_MASTER_KEY*)OPENSSL_malloc(sizeof(SM9_SIGN_MASTER_KEY));
    if (!msk) {
        return nullptr;
    }

    if (sm9_sign_master_key_generate(msk) != 1) {
        OPENSSL_free(msk);
        return nullptr;
    }

    EVP_PKEY *pkey = sign_master_key_to_pkey(msk, false);
    OPENSSL_free(msk);
    return pkey;
}

/* 从 EVP_PKEY 提取主密钥 */
bool sign_master_key_from_pkey(SM9_SIGN_MASTER_KEY *msk, const EVP_PKEY *pkey) {
    if (!msk) return false;

    SM9KeyData *data = static_cast<SM9KeyData*>(EVP_PKEY_get0(pkey));
    if (!data || data->key_type != 1) {
        return false;
    }

    memcpy(msk, &data->u.sign_master, sizeof(SM9_SIGN_MASTER_KEY));
    return true;
}

/* 从主密钥派生用户签名密钥 */
EVP_PKEY *derive_sign_user_key(const EVP_PKEY *master_pkey, const std::string &id) {
    if (!master_pkey) return nullptr;

    SM9_SIGN_MASTER_KEY msk;
    SM9_SIGN_KEY user_key;

    if (!sign_master_key_from_pkey(&msk, master_pkey)) {
        return nullptr;
    }

    if (sm9_sign_master_key_extract_key(&msk, id.c_str(), id.size(), &user_key) != 1) {
        return nullptr;
    }

    return sign_key_to_pkey(&user_key);
}

/* 从 EVP_PKEY 提取用户密钥 */
bool sign_key_from_pkey(SM9_SIGN_KEY *key, const EVP_PKEY *pkey) {
    if (!key) return false;

    SM9KeyData *data = static_cast<SM9KeyData*>(EVP_PKEY_get0(pkey));
    if (!data || data->key_type != 3) {
        return false;
    }

    memcpy(key, &data->u.sign_key, sizeof(SM9_SIGN_KEY));
    return true;
}

/* SM9 主密钥转换为 EVP_PKEY */
EVP_PKEY *sign_master_key_to_pkey(const SM9_SIGN_MASTER_KEY *msk, bool public_only) {
    if (!msk) return nullptr;

    SM9KeyData *data = new SM9KeyData();
    data->key_type = 1;
    data->is_public_only = public_only;
    memcpy(&data->u.sign_master, msk, sizeof(SM9_SIGN_MASTER_KEY));

    if (public_only) {
        memset(&data->u.sign_master.ks, 0, sizeof(sm9_z256_t));
    }

    return create_pkey_with_sm9_data(1, data);
}

/* SM9 用户密钥转换为 EVP_PKEY */
EVP_PKEY *sign_key_to_pkey(const SM9_SIGN_KEY *key) {
    if (!key) return nullptr;

    SM9KeyData *data = new SM9KeyData();
    data->key_type = 3;
    data->is_public_only = false;
    memcpy(&data->u.sign_key, key, sizeof(SM9_SIGN_KEY));

    return create_pkey_with_sm9_data(3, data);
}

/* 将 SM9 主密钥转换为 DER */
bool sign_master_public_key_to_der(const EVP_PKEY *pkey, unsigned char **out, size_t *outlen) {
    if (!pkey || !out || !outlen) return false;

    SM9_SIGN_MASTER_KEY msk;
    if (!sign_master_key_from_pkey(&msk, pkey)) {
        return false;
    }

    return sm9_sign_master_public_key_to_der(&msk, out, outlen) == 1;
}

/* 从 DER 数据解析 SM9 主密钥 */
EVP_PKEY *sign_master_public_key_from_der(const unsigned char *der, size_t derlen) {
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

/* 释放 DER 数据 */
void free_der_data(unsigned char *data) {
    if (data) free(data);
}

} // namespace sm9_bridge
