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
		QByteArray encKey; // �洢������ʽ��˽Կ
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
		static QString passHash; // ���ݿ������ϣ
		static Passwd passwd; // ���ڼ���/���ܵ�����
		static QString md5passwd(QByteArray pass); // MD5�����ϣ����
		static QString sha512passwd(QByteArray pass, QString salt); // SHA512�����ϣ����
		static QString sha512passwT(QByteArray pass, QString salt); // SHA512�����ϣ����
		static bool validateDatabasePassword(const Passwd &passwd); // ��֤���ݿ�����

		pki_evp(const QString &n = QString(), int type = EVP_PKEY_RSA); // ���캯����Ĭ�ϴ���RSA��Կ
		pki_evp(const pki_evp *pkey); // �������캯��
		pki_evp(EVP_PKEY *pkey); // ��OpenSSL EVP_PKEY����
		virtual ~pki_evp();

		void generate(const keyjob &task); // ��������Կ
		void setOwnPass(enum passType); // ������������
		void set_evp_key(EVP_PKEY *pkey); // ����EVP��Կ
		void encryptKey(const char *password = NULL); // ������Կ
		void bogusEncryptKey(); // ����α������Կ
		bool updateLegacyEncryption(); // ���¾ɰ���ܷ�ʽ
		EVP_PKEY *decryptKey() const; // ������Կ
		EVP_PKEY *tryDecryptKey() const; // ���Խ�����Կ
		EVP_PKEY *legacyDecryptKey(QByteArray &myencKey,
					Passwd &ownPassBuf) const; // ʹ�þɰ淽ʽ������Կ
		EVP_PKEY *priv2pub(EVP_PKEY* key); // ��˽Կת��Ϊ��Կ
		static QString removeTypeFromIntName(QString n); // ���ڲ��������Ƴ�������Ϣ
		void fromPEMbyteArray(const QByteArray &ba, const QString &name); // ��PEM��ʽ�ֽ����鵼��
		void fload(const QString &fname); // ���ļ�������Կ
		virtual bool pem(BioByteArray &b, const pki_export *xport); // ת��ΪPEM��ʽ
		EVP_PKEY *load_ssh_ed25519_privatekey(const QByteArray &ba,
						const pass_info &p); // ����SSH ED25519˽Կ
		void writeDefault(const QString &dirname) const; // д��Ĭ���ļ�
		void writeKey(XFile &file, const EVP_CIPHER *enc,
				pem_password_cb *cb, bool pem) const; // д����Կ���ļ�
		void writePKCS8(XFile &file, const EVP_CIPHER *enc,
				pem_password_cb *cb, bool pem) const; // д��PKCS8��ʽ��Կ
		void writePVKprivate(XFile &file) const; // д��Microsoft PVK��ʽ˽Կ
		void writeSSH2private(XFile &file) const; // д��SSH2��ʽ˽Կ
		void write_SSH2_ed25519_private(BIO *b, const EVP_PKEY *pkey) const; // д��SSH2 ED25519˽Կ
		void fillJWK(QJsonObject &json, const pki_export *xport) const; // ���JSON Web Key
		bool verify(EVP_PKEY *pkey) const; // ��֤��Կ
		QVariant getIcon(const dbheader *hd) const; // ��ȡͼ��
		bool sqlUpdatePrivateKey(); // �������ݿ��е�˽Կ
		QSqlError insertSqlData(); // ����SQL����
		QSqlError deleteSqlData(); // ɾ��SQL����
		void restoreSql(const QSqlRecord &rec); // ��SQL��¼�ָ�
};

#endif
