/* vi: set sw=4 ts=4:
 *
 * Copyright (C) 2001 - 2020 Christian Hohnstaedt.
 *
 * All rights reserved.
 */

#ifndef __PKI_EVP_H
#define __PKI_EVP_H

#include <QString>
#include <QProgressBar>
#include <openssl/pem.h>
#include <openssl/evp.h>
#include "pki_key.h"
#include "Passwd.h"

#define VIEW_private_ownpass 9

class pass_info;

class pki_evp: public pki_key
{
		Q_OBJECT
		QByteArray encKey; // 存储加密形式的私钥
		void init();
		QByteArray getEncKey() const;
		QString encKey_b64()
		{
			return QString::fromLatin1(encKey.toBase64());
		}
		static QString _sha512passwd(QByteArray pass, QString salt,
						int size, int repeat);
		void set_EVP_PKEY(EVP_PKEY *pkey, QString name = QString());

	protected:
		bool openssl_pw_error() const;

	public:
		static QString passHash; // 数据库密码哈希
		static Passwd passwd; // 用于加密/解密的密码
		static QString md5passwd(QByteArray pass); // MD5密码哈希函数
		static QString sha512passwd(QByteArray pass, QString salt); // SHA512密码哈希函数
		static QString sha512passwT(QByteArray pass, QString salt); // SHA512密码哈希变种
		static bool validateDatabasePassword(const Passwd &passwd); // 验证数据库密码

		pki_evp(const QString &n = QString(), int type = EVP_PKEY_RSA); // 构造函数，默认创建RSA密钥
		pki_evp(const pki_evp *pkey); // 拷贝构造函数
		pki_evp(EVP_PKEY *pkey); // 从OpenSSL EVP_PKEY构造
		virtual ~pki_evp();

		void generate(const keyjob &task); // 生成新密钥
		void setOwnPass(enum passType); // 设置密码类型
		void set_evp_key(EVP_PKEY *pkey); // 设置EVP密钥
		void encryptKey(const char *password = NULL); // 加密密钥
		void bogusEncryptKey(); // 创建伪加密密钥
		bool updateLegacyEncryption(); // 更新旧版加密方式
		EVP_PKEY *decryptKey() const; // 解密密钥
		EVP_PKEY *tryDecryptKey() const; // 尝试解密密钥
		EVP_PKEY *legacyDecryptKey(QByteArray &myencKey,
					Passwd &ownPassBuf) const; // 使用旧版方式解密密钥
		EVP_PKEY *priv2pub(EVP_PKEY* key); // 将私钥转换为公钥
		static QString removeTypeFromIntName(QString n); // 从内部名称中移除类型信息
		void fromPEMbyteArray(const QByteArray &ba, const QString &name); // 从PEM格式字节数组导入
		void fload(const QString &fname); // 从文件加载密钥
		virtual bool pem(BioByteArray &b, const pki_export *xport); // 转换为PEM格式
		EVP_PKEY *load_ssh_ed25519_privatekey(const QByteArray &ba,
						const pass_info &p); // 加载SSH ED25519私钥
		void writeDefault(const QString &dirname) const; // 写入默认文件
		void writeKey(XFile &file, const EVP_CIPHER *enc,
				pem_password_cb *cb, bool pem) const; // 写入密钥到文件
		void writePKCS8(XFile &file, const EVP_CIPHER *enc,
				pem_password_cb *cb, bool pem) const; // 写入PKCS8格式密钥
		void writePVKprivate(XFile &file) const; // 写入Microsoft PVK格式私钥
		void writeSSH2private(XFile &file) const; // 写入SSH2格式私钥
		void write_SSH2_ed25519_private(BIO *b, const EVP_PKEY *pkey) const; // 写入SSH2 ED25519私钥
		void fillJWK(QJsonObject &json, const pki_export *xport) const; // 填充JSON Web Key
		bool verify(EVP_PKEY *pkey) const; // 验证密钥
		QVariant getIcon(const dbheader *hd) const; // 获取图标
		bool sqlUpdatePrivateKey(); // 更新数据库中的私钥
		QSqlError insertSqlData(); // 插入SQL数据
		QSqlError deleteSqlData(); // 删除SQL数据
		void restoreSql(const QSqlRecord &rec); // 从SQL记录恢复
};

#endif
