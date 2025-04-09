/* vi: set sw=4 ts=4:
 *
 * Copyright (C) 2001 - 2015 Christian Hohnstaedt.
 *
 * All rights reserved.
 */


#include "db_key.h"
#include "pki_evp.h"

#include "pki_scard.h"
#include "pki_x509super.h"

#include "exception.h"
#include "pkcs11.h"

#include "XcaWarningCore.h"
#include "PwDialogCore.h"
#include <QMessageBox>
#include <QProcess>
#include <QDir>
#include <QDateTime>
#include <openssl/bio.h>
#include <QCoreApplication>

db_key::db_key() : db_base("keys")
{
	sqlHashTable = "public_keys";
	pkitype << asym_key << smartCard;
	updateHeaders();
	loadContainer();
}

void db_key::loadContainer()
{
	XSqlQuery q;

	db_base::loadContainer();
	foreach(pki_key *key, Store.getAll<pki_key>())
		key->setUcount(0);

	SQL_PREPARE(q, "SELECT pkey, COUNT(*) FROM x509super WHERE pkey IS NOT NULL GROUP by pkey");
	q.exec();
	while (q.next()) {
		pki_key *key = Store.lookupPki<pki_key>(q.value(0));
		if (!key) {
			qDebug() << "Unknown key" << q.value(0).toULongLong();
			continue;
		}
		key->setUcount(q.value(1).toInt());
	}
	XCA_SQLERROR(q.lastError());
}

dbheaderList db_key::getHeaders()
{
	dbheaderList h = db_base::getHeaders();
	h <<	new dbheader(HD_key_type, true, tr("Type")) <<
		new num_dbheader(HD_key_size, true, tr("Size")) <<
#ifndef OPENSSL_NO_EC
		new dbheader(HD_key_curve, false,tr("EC Group")) <<
#endif
		new num_dbheader(HD_key_use, true, tr("Use")) <<
		new dbheader(HD_key_passwd, true, tr("Password"));
	return h;
}

pki_base *db_key::newPKI(enum pki_type type)
{
	if (type == asym_key)
		return new pki_evp("");
	return new pki_scard("");
}

QList<pki_key *> db_key::getAllKeys()
{
	return Store.sqlSELECTpki<pki_key>("SELECT item from public_keys");
}

QList<pki_key *> db_key::getUnusedKeys()
{
	return Store.sqlSELECTpki<pki_key>(
		"SELECT public_keys.item FROM public_keys "
		"LEFT OUTER JOIN x509super ON x509super.pkey= public_keys.item "
		"WHERE x509super.item IS NULL");
}

void db_key::remFromCont(const QModelIndex &idx)
{
	db_base::remFromCont(idx);
	XSqlQuery q;

	QList<pki_x509super*> items = Store.sqlSELECTpki<pki_x509super>(
		"SELECT item FROM x509super WHERE pkey is NULL");
	foreach(pki_x509super *x509s, items) {
		x509s->setRefKey(NULL);
	}
	/* "UPDATE x509super SET pkey=NULL WHERE pkey=?" done in
	 * pki->deleteSqlData() */
}

void db_key::inToCont(pki_base *pki)
{
	db_base::inToCont(pki);
	pki_key *key = static_cast<pki_key*>(pki);
	unsigned hash = key->hash();
	QList<pki_x509super*> items = Store.sqlSELECTpki<pki_x509super>(
		"SELECT item FROM x509super WHERE pkey IS NULL AND key_hash=?",
		QList<QVariant>() << QVariant(hash));
	XSqlQuery q;
	SQL_PREPARE(q, "UPDATE x509super SET pkey=? WHERE item=?");
	q.bindValue(0, key->getSqlItemId());
	foreach(pki_x509super *x509s, items) {
		if (!x509s->compareRefKey(key))
			continue;
		/* Found item matching this key */
		x509s->setRefKey(key);
		q.bindValue(1, x509s->getSqlItemId());
		AffectedItems(x509s->getSqlItemId());
		q.exec();
		XCA_SQLERROR(q.lastError());
	}
}

pki_base* db_key::insert(pki_base *item)
{
	pki_key *lkey = dynamic_cast<pki_key *>(item);
	pki_key *oldkey;
	pki_evp *evp = dynamic_cast<pki_evp*>(lkey);

	if (evp)
		evp->setOwnPass(pki_evp::ptCommon);

	oldkey = static_cast<pki_key *>(getByReference(lkey));
	if (oldkey != NULL) {
		if ((oldkey->isPrivKey() && lkey->isPrivKey()) || lkey->isPubKey()){
			XCA_INFO(
			tr("The key is already in the database as:\n'%1'\nand is not going to be imported").arg(oldkey->getIntName()));
			delete lkey;
			return NULL;
		} else {
			XCA_INFO(
			tr("The database already contains the public part of the imported key as\n'%1\nand will be completed by the new, private part of the key").arg(oldkey->getIntName()));
			lkey->setComment(oldkey->getComment());
			lkey->selfComment(tr("Extending public key from %1 by imported key '%2'")
				.arg(oldkey->getInsertionDate().toPretty())
				.arg(lkey->getIntName()));
			lkey->setIntName(oldkey->getIntName());
			deletePKI(index(oldkey));
		}
	}
	return insertPKI(lkey);
}

pki_key *db_key::newKey(const keyjob &job, const QString &name)
{
	// 处理 SM9 密钥
	if (job.isSM9()) {
		return newIdentKey(job, name);
	}
	
	pki_key *key = NULL;

	if (!job.isEC() && !job.isED25519()) {
		if (job.size < 32) {
			XCA_WARN(tr("Key size too small !"));
			return NULL;
		}
		if (job.size < 1024 || job.size > 8192)
			if (!XCA_YESNO(tr("You are sure to create a key of the size: %1 ?").arg(job.size))) {
				return NULL;
			}
	}
	try {
		if (job.isToken()) {
			key = new pki_scard(name);
		} else {
			key = new pki_evp(name);
		}
		key->generate(job);
		key->pkiSource = generated;
		if (key->getIntName().isEmpty())
			key->autoIntName(name);
		key = dynamic_cast<pki_key*>(insert(key));
		emit keyDone(key);
		createSuccess(key);

	} catch (errorEx &err) {
		delete key;
		key = NULL;
		XCA_ERROR(err);
	}
	return key;
}


int db_key::exportFlags(const QModelIndex &index) const
{
	int disable_flags = 0;

	pki_key *key = fromIndex<pki_key>(index);

	if (!index.isValid() || !key)
		return 0;

	int keytype = key->getKeyType();
	if (keytype != EVP_PKEY_RSA && keytype != EVP_PKEY_DSA)
		disable_flags |= F_PVK;
#ifdef EVP_PKEY_ED25519
	if (keytype == EVP_PKEY_ED25519)
		disable_flags |= F_TRADITION;
#endif
	if (!key->SSH2_compatible())
		disable_flags |= F_SSH2;

	if (key->isPubKey() || key->isToken())
		disable_flags |= F_PRIVATE;
	if (keytype != EVP_PKEY_RSA && key->getJWKcrv().isEmpty())
		disable_flags |= F_JWK;

	return disable_flags;
}

void db_key::exportItem(const QModelIndex &index, const pki_export *xport,
			XFile &file) const
{
	const EVP_CIPHER *algo = NULL;
	pki_key *key = fromIndex<pki_key>(index);
	pki_evp *privkey = dynamic_cast<pki_evp *>(key);

	int(*pwCallback)(char *, int, int, void *) = NULL;

	if (xport->match_all(F_CRYPT)) {
		algo = EVP_aes_256_cbc();
		pwCallback = PwDialogCore::pwCallback;
	}

	if (privkey && xport->match_all(F_DER | F_PRIVATE))
		privkey->writeKey(file, NULL, NULL, false);
	else if (privkey && xport->match_all(F_PEM | F_PRIVATE))
		privkey->writeKey(file, algo, pwCallback, true);
	else if (xport->match_all(F_DER))
		key->writePublic(file, false);
	else if (xport->match_all(F_PEM))
		key->writePublic(file, true);
	else if (privkey && xport->match_all(F_PKCS8))
		privkey->writePKCS8(file, algo, pwCallback, true);
	else if (privkey && xport->match_all(F_SSH2 | F_PRIVATE))
		privkey->writeSSH2private(file);
	else if (xport->match_all(F_SSH2))
		key->writeSSH2public(file);
	else if (privkey && xport->match_all(F_PVK))
		privkey->writePVKprivate(file);
	else
		db_base::exportItem(index, xport, file);
}

void db_key::updateKeyEncryptionScheme()
{
	bool common_success = true;
	if (!pki_evp::validateDatabasePassword(pki_evp::passwd))
		return;
	if (Settings["legacy-keys-updated"])
		return;

	QList<pki_evp *> privates, withOwnPassword;
	privates = Store.sqlSELECTpki<pki_evp>("SELECT item from private_keys");

	qDebug() << "Updating encryption scheme of" << privates.size() << "keys";

	Transaction;
	if (!TransBegin())
		return;

	for (pki_evp *key : privates) {
		if (key->isPubKey()) {
			qWarning() << "BUG: private key" << key << "is not private";
			continue; // Should not happen
		}
		bool conv_success = key->updateLegacyEncryption();
		if (!conv_success && key->getOwnPass() == pki_key::ptPrivate) {
			withOwnPassword << key;
		} else {
			common_success &= conv_success;
		}
	}
	qDebug() << "Success:" << common_success << "Legacy keys:"
			<< withOwnPassword.size();
	ign_openssl_error();
	TransCommit();
	if (withOwnPassword.size() > 0) {
		QString items;
		for (pki_evp *key : withOwnPassword)
			items += "'" + key->getIntName() + "' ";
		XCA_WARN(tr("Internal key update: The keys: %1 must be updated once by resetting and setting its private password").arg(items));
	}
	if (common_success && withOwnPassword.isEmpty())
		Settings["legacy-keys-updated"] = true;
}

void db_key::setOwnPass(QModelIndex idx, enum pki_key::passType x)
{
	pki_evp *targetKey = fromIndex<pki_evp>(idx);
	enum pki_key::passType old_type;

	if (!idx.isValid() || !targetKey)
		return;
	if (targetKey->isToken()) {
		throw errorEx(tr("Tried to change password of a token"));
	}
	old_type = targetKey->getOwnPass();
	targetKey->setOwnPass(x);
	if (!targetKey->sqlUpdatePrivateKey())
		targetKey->setOwnPass(old_type);
}

// 处理 SM9 密钥生成
pki_key *db_key::newIdentKey(const keyjob &job, const QString &name)
{
	qDebug() << "Starting SM9 key generation with parameters:";
	qDebug() << "  Type:" << job.sm9Type;
	qDebug() << "  User ID:" << job.userId;
	qDebug() << "  Name:" << name;

	if (job.sm9Type.isEmpty() || job.userId.isEmpty()) {
		qDebug() << "Error: SM9 parameters incomplete";
		QMessageBox::warning(NULL, XCA_TITLE, tr("SM9 parameters incomplete"));
		return NULL;
	}
	
	// 检查GmSSL是否可用
	{
		QProcess process;
		process.start("gmssl", QStringList() << "version");
		if (!process.waitForStarted(3000) || !process.waitForFinished(3000)) {
			qDebug() << "Error: GmSSL not available";
			QMessageBox::warning(NULL, XCA_TITLE, 
				tr("GmSSL not found. Please ensure GmSSL is installed and added to PATH."));
			return NULL;
		}
		qDebug() << "GmSSL version:" << QString::fromUtf8(process.readAll()).trimmed();
	}
	
	// 设置sm9keygen.sh脚本路径
	QStringList searchPaths;
	QString appDir = QCoreApplication::applicationDirPath();
	qDebug() << "Application directory:" << appDir;
	
	searchPaths << appDir + "/misc/sm9keygen.sh"               // 应用程序目录下的misc
			   << appDir + "/../misc/sm9keygen.sh"             // 上级目录的misc
			   << appDir + "/../share/xca/misc/sm9keygen.sh"   // 标准安装位置
			   << "/usr/share/xca/misc/sm9keygen.sh"           // Linux系统标准位置
			   << "/usr/local/share/xca/misc/sm9keygen.sh"     // Linux本地安装位置
			   << appDir + "/share/xca/misc/sm9keygen.sh"      // 另一种可能的路径
			   << appDir + "/../share/misc/sm9keygen.sh"       // 另一种可能的路径
			   << "../misc/sm9keygen.sh"                       // 相对于工作目录
			   << "misc/sm9keygen.sh";                         // 项目目录
	
	// 调试信息：记录所有可能的脚本路径
	qDebug() << "SM9 script search paths:";
	foreach (const QString &path, searchPaths) {
		qDebug() << "  Checking path:" << path << "exists:" << QFile::exists(path);
	}
	
	QString scriptPath;
	foreach (const QString &path, searchPaths) {
		if (QFile::exists(path)) {
			scriptPath = path;
			qDebug() << "Found SM9 script at:" << scriptPath;
			break;
		}
	}
	
	if (scriptPath.isEmpty()) {
		// 脚本未找到，显示当前应用程序信息
		qDebug() << "Application directory:" << appDir;
		qDebug() << "Current working directory:" << QDir::currentPath();
		
		// 列出当前目录下的文件
		QDir currentDir = QDir::current();
		qDebug() << "Files in current directory:" << currentDir.entryList(QDir::Files);
		
		// 尝试列出misc目录下的文件
		QDir miscDir(appDir + "/misc");
		if (miscDir.exists()) {
			qDebug() << "Files in" << miscDir.path() << ":" << miscDir.entryList(QDir::Files);
		}
		
		QMessageBox::warning(NULL, XCA_TITLE, 
			tr("SM9 key generation script not found, please ensure correct installation"));
		return NULL;
	}
	
	// 设置脚本执行权限
	QProcess::execute("chmod", QStringList() << "+x" << scriptPath);
	
	// 创建临时目录用于存储生成的密钥
	QString tempDir = QDir::tempPath() + "/xca_sm9_" + 
					 QString::number(QDateTime::currentMSecsSinceEpoch());
	QDir().mkpath(tempDir);
	
	// 设置用户密钥输出路径
	QString userKeyPath = tempDir + "/user_key.pem";
	
	// 构建脚本参数 - 按照新脚本格式修改
	QStringList args;
	
	// 直接添加参数，无需使用 -type 等标志
	args << job.sm9Type;
	args << job.userId;
	args << job.masterKeyPass;
	
	// 输出调试信息
	qDebug() << "Running SM9 script:" << scriptPath;
	qDebug() << "Arguments:" << args;
	qDebug() << "Working directory:" << tempDir;
	
	// 执行脚本命令
	QProcess process;
	process.setWorkingDirectory(tempDir);  // 设置工作目录
	process.setProcessChannelMode(QProcess::MergedChannels); // 合并标准输出和错误输出
	process.start("bash", QStringList() << scriptPath << args);
	
	if (!process.waitForStarted(5000)) {
		QMessageBox::warning(NULL, XCA_TITLE, 
			tr("SM9 key generation process failed to start"));
		QDir(tempDir).removeRecursively();
		return NULL;
	}
	
	if (!process.waitForFinished(30000)) {
		process.kill();
		QMessageBox::warning(NULL, XCA_TITLE, tr("SM9 key generation timeout"));
		QDir(tempDir).removeRecursively();
		return NULL;
	}
	
	// 读取脚本输出
	QString scriptOutput = QString::fromUtf8(process.readAll());
	qDebug() << "Script output:" << scriptOutput;
	
	// 检查脚本是否成功执行
	int exitCode = process.exitCode();
	qDebug() << "Script exit code:" << exitCode;
	
	if (exitCode != 0) {
		QMessageBox::warning(NULL, XCA_TITLE, 
						   tr("SM9 key generation failed: %1").arg(scriptOutput));
		QDir(tempDir).removeRecursively();
		return NULL;
	}
	
	// 获取生成的密钥文件路径
	QString generatedKeyFile;
	if (job.sm9Type == "sm9sign") {
		generatedKeyFile = tempDir + "/sm9sign_" + job.userId + ".pem";
	} else {
		generatedKeyFile = tempDir + "/sm9enc_" + job.userId + ".pem";
	}
	
	// 检查文件是否存在
	if (!QFile::exists(generatedKeyFile)) {
		qDebug() << "Expected key file not found:" << generatedKeyFile;
		qDebug() << "Files in temp directory:" << QDir(tempDir).entryList(QDir::Files);
		
		QMessageBox::warning(NULL, XCA_TITLE, 
			tr("Generated key file not found: %1").arg(generatedKeyFile));
		QDir(tempDir).removeRecursively();
		return NULL;
	}
	
	// 后续导入密钥到数据库流程...
	try {
		// 导入用户密钥
		BIO *bio_user = BIO_new_file(generatedKeyFile.toUtf8().constData(), "r");
		if (!bio_user) {
			QMessageBox::warning(NULL, XCA_TITLE, tr("Cannot open user key file"));
			QDir(tempDir).removeRecursively();
			return NULL;
		}
		pki_evp *userKey = new pki_evp(name);
		userKey->fromPEM_BIO(bio_user, job.masterKeyPass.toUtf8().constData());
		BIO_free(bio_user);
		userKey = dynamic_cast<pki_evp*>(insert(userKey));
		
		// 删除临时文件
		QDir(tempDir).removeRecursively();
		
		// 通知密钥生成完成
		if (userKey) {
			emit keyDone(userKey);
			createSuccess(userKey);
		}
		
		return userKey;
	} catch (errorEx &err) {
		QMessageBox::warning(NULL, XCA_TITLE, 
						   tr("Failed to import generated key: %1").arg(err.getString()));
		QDir(tempDir).removeRecursively();
		return NULL;
	}
}

