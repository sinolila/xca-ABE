/* vi: set sw=4 ts=4:
 *
 * Copyright (C) 2001 - 2020 Christian Hohnstaedt.
 *
 * All rights reserved.
 */

#ifndef __PKI_KEY_H
#define __PKI_KEY_H

#include <QString>
#include <QJsonObject>
#include <openssl/rsa.h>
#include <openssl/bn.h>
#include <openssl/pem.h>
#include <openssl/evp.h>
#include "pki_base.h"
#include "builtin_curves.h"

#define PEM_STRING_OPENSSH_KEY "OPENSSH PRIVATE KEY"
#define DEFAULT_KEY_LENGTH 2048
#define ED25519_KEYLEN 32

#define VIEW_public_keys_type 6
#define VIEW_public_keys_len 7
#define VIEW_public_keys_public 8

extern builtin_curves builtinCurves;

// ���SM9��Կ���ͳ�������
#ifndef EVP_PKEY_SM9
#define EVP_PKEY_SM9_SIGN 406
#define EVP_PKEY_SM9_ENC  407
#endif

class keytype
{
  public:
	static QList<keytype> types()
	{
		return QList<keytype> {
			keytype(EVP_PKEY_RSA, "RSA", CKM_RSA_PKCS_KEY_PAIR_GEN,
				false, true),
			keytype(EVP_PKEY_DSA, "DSA", CKM_DSA_KEY_PAIR_GEN,
				false, true),
#ifndef OPENSSL_NO_EC
			keytype(EVP_PKEY_EC, "EC", CKM_EC_KEY_PAIR_GEN,
				true, false),
#ifdef EVP_PKEY_ED25519
			keytype(EVP_PKEY_ED25519, "ED25519", CKM_VENDOR_DEFINED, false, false),
#endif
#ifdef EVP_PKEY_SM9
			keytype(EVP_PKEY_SM9_SIGN, "SM9_SIGN", CKM_VENDOR_DEFINED, false, false),
			keytype(EVP_PKEY_SM9_ENC, "SM9_ENC", CKM_VENDOR_DEFINED, false, false),
#endif
#endif
		};
	}
	int type{};
	QString name{};
	CK_MECHANISM_TYPE mech{};
	bool curve{}, length{};

	keytype(int t, const QString &n, CK_MECHANISM_TYPE m, bool c, bool l)
			: type(t), name(n), mech(m), curve(c), length(l) { }
	keytype() : type(-1), name(QString()), mech(0),
			curve(false), length(true) { }
	bool isValid()
	{
		return type != -1;
	}
	QString traditionalPemName() const
	{
		return
#ifdef EVP_PKEY_ED25519
			type == EVP_PKEY_ED25519 ? QString("PRIVATE KEY") :
#endif
#ifdef EVP_PKEY_SM9
			type == EVP_PKEY_SM9_SIGN ? QString("SM9 SIGN PRIVATE KEY") :
			type == EVP_PKEY_SM9_ENC ? QString("SM9 ENC PRIVATE KEY") :
#endif
				QString("%1 PRIVATE KEY").arg(name);
	}
	static const keytype byType(int type)
	{
		foreach(const keytype t, types()) {
			if (t.type == type)
				return t;
		}
		return keytype();
	}
	static const keytype byMech(CK_MECHANISM_TYPE mech)
	{
		foreach(const keytype t, types()) {
			if (t.mech == mech)
				return t;
		}
		return keytype();
	}
	static const keytype byName(const QString &name)
	{
		foreach(const keytype t, types()) {
			if (t.name == name.toUpper())
				return t;
		}
		return keytype();
	}
	static const keytype byPKEY(EVP_PKEY *pkey)
	{
		return byType(EVP_PKEY_type(EVP_PKEY_id(pkey)));
	}
};

class keyjob
{
  public:
	static keyjob defaultjob;
	keytype ktype;
	int size;
	int ec_nid;
	slotid slot;
	keyjob() {
		size = DEFAULT_KEY_LENGTH;
		ktype = keytype::byName("RSA");
		ec_nid = NID_undef;
		slot = slotid();
	}
	keyjob(const QString &desc)
	{
		QStringList sl = desc.split(':');
		if (sl.size() == 1)
			sl += "";
		if (sl.size() != 2)
			return;
		ktype = keytype::byName(sl[0]);
		size = DEFAULT_KEY_LENGTH;
		ec_nid = NID_undef;
		if (isEC())
			ec_nid = OBJ_txt2nid(sl[1].toLatin1());
		else if (!isED25519())
			size = sl[1].toInt();
		slot = slotid();
		ign_openssl_error();
	}
	QString toString()
	{
		if (isED25519())
			return ktype.name;
		return QString("%1:%2").arg(ktype.name) .arg(isEC() ?
					OBJ_obj2QString(OBJ_nid2obj(ec_nid)) :
					QString::number(size));
	}
	bool isToken() const
	{
		return slot.lib != NULL;
	}
	bool isEC() const
	{
		return ktype.type == EVP_PKEY_EC;
	}
	bool isED25519() const
	{
#ifdef EVP_PKEY_ED25519
		return ktype.type == EVP_PKEY_ED25519;
#else
		return false;
#endif
	}
	bool isValid()
	{
		if (!ktype.isValid())
			return false;
		if (isED25519())
			return true;
		if (isEC() && builtinCurves.containNid(ec_nid))
			return true;
		if (!isEC() && size > 0)
			return true;
		return false;
	}
};

class pki_key: public pki_base
{

		Q_OBJECT
	friend class pki_x509super;

	public:
		enum passType { ptCommon, ptPrivate, ptBogus, ptPin };

	protected:
		enum passType ownPass;
		int key_size;
		bool isPub;
		EVP_PKEY *key;
		QString BN2QString(const BIGNUM *bn) const;
		QByteArray SSH2publicQByteArray(bool raw=false) const;
		QByteArray X509_PUBKEY_public_key() const;
		QByteArray PEM_comment() const;
		void collect_properties(QMap<QString, QString> &prp) const;

		BIGNUM *ssh_key_data2bn(QByteArray *ba) const;
		void ssh_key_check_chunk(QByteArray *ba, const char *expect) const;
		QByteArray ssh_key_next_chunk(QByteArray *ba) const;
		void ssh_key_QBA2data(const QByteArray &ba,
					QByteArray *data) const;
		void ssh_key_bn2data(const BIGNUM *bn, QByteArray *data) const;

	private:
		mutable int useCount; // usage counter

	public:

		pki_key(const QString &name = QString());
		pki_key(const pki_key *pk);
		virtual ~pki_key();

		void autoIntName(const QString &file);
		QString length() const;
		QString comboText() const;
		QString getKeyTypeString(void) const;
		virtual EVP_PKEY *decryptKey() const = 0;
		virtual bool isToken();
		virtual QString getTypeString(void) const;
		virtual QList<int> possibleHashNids();
		QString getMsg(msg_type msg, int n = 1) const;

		void writePublic(XFile &file, bool pem) const;
		QString getJWKcrv() const;
		void fillJWK(QJsonObject &json, const pki_export *xport) const;
		bool compare(const pki_base *ref) const;
		int getKeyType() const;
		bool isPrivKey() const;
		virtual bool verify(EVP_PKEY *pkey) const;
		int getUcount() const;
		void setUcount(int c)
		{
			useCount = c;
		}
		enum passType getOwnPass(void)
		{
			return ownPass;
		}
		EVP_PKEY *getPubKey()
		{
			return key;
		}
		bool isPubKey() const
		{
			return isPub;
		}
		virtual void generate(const keyjob &)
		{
			qFatal("generate in pki_key");
		}
		bool pem(BioByteArray &);
		virtual bool pem(BioByteArray &b, const pki_export *xport);
		QVariant column_data(const dbheader *hd) const;
		QString modulus() const;
		QString pubEx() const;
		QString subprime() const;
		QString pubkey() const;

#ifndef OPENSSL_NO_EC
		int ecParamNid() const;
		QString ecPubKey() const;
		QByteArray ed25519PubKey() const;
		QByteArray ed25519PrivKey(const EVP_PKEY *pkey) const;
		BIGNUM *ecPubKeyBN() const;
#ifdef EVP_PKEY_SM9
		QByteArray sm9SignMasterPubKey() const;
		QByteArray sm9EncMasterPubKey() const;
		QByteArray sm9SignPrivKey() const;
		QByteArray sm9EncPrivKey() const;
#endif
#endif
		void d2i(QByteArray &ba);
		void d2i_old(QByteArray &ba, int type);
		QByteArray i2d() const;
		EVP_PKEY *load_ssh2_key(const QByteArray &ba);
		void writeSSH2public(XFile &file) const;
		QString fingerprint(const QString &format) const;
		bool SSH2_compatible() const;
		void print(BioByteArray &b, enum print_opt opt) const;
		void resetUcount()
		{
			useCount = -1;
		}
		QSqlError insertSqlData();
		QSqlError deleteSqlData();
		void restoreSql(const QSqlRecord &rec);
};

Q_DECLARE_METATYPE(pki_key *);
#endif
