/* vi: set sw=4 ts=4:
 *
 * Copyright (C) 2001 - 2015 Christian Hohnstaedt.
 *
 * All rights reserved.
 */

#include "db_sm9.h"
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

db_sm9::db_sm9() : db_base("sm9keys")
{
    sqlHashTable = "sm9_keys";
    pkitype << asym_key;
    updateHeaders();
    loadContainer();
}

void db_sm9::loadContainer()
{
    XSqlQuery q;

    db_base::loadContainer();
    foreach(pki_key *key, Store.getAll<pki_key>()) {
        // 只加载SM9密钥
        if (key->getKeyType() == EVP_PKEY_SM9_SIGN || 
            key->getKeyType() == EVP_PKEY_SM9_ENC) {
            key->setUcount(0);
        }
    }

    SQL_PREPARE(q, "SELECT pkey, COUNT(*) FROM x509super WHERE pkey IS NOT NULL GROUP by pkey");
    q.exec();
    while (q.next()) {
        pki_key *key = Store.lookupPki<pki_key>(q.value(0));
        if (!key) {
            qDebug() << "Unknown key" << q.value(0).toULongLong();
            continue;
        }
        // 只处理SM9密钥
        if (key->getKeyType() == EVP_PKEY_SM9_SIGN || 
            key->getKeyType() == EVP_PKEY_SM9_ENC) {
            key->setUcount(q.value(1).toInt());
        }
    }
    XCA_SQLERROR(q.lastError());
}

dbheaderList db_sm9::getHeaders()
{
    dbheaderList h = db_base::getHeaders();
    h << new dbheader(HD_key_type, true, tr("Type")) <<
         new num_dbheader(HD_key_size, true, tr("Size")) <<
         new num_dbheader(HD_key_use, true, tr("Use")) <<
         new dbheader(HD_key_passwd, true, tr("Password"));
    return h;
}

pki_base *db_sm9::newPKI(enum pki_type type)
{
    if (type == asym_key)
        return new pki_evp("");
    return new pki_scard("");
}

QList<pki_key *> db_sm9::getSM9Keys()
{
    return Store.sqlSELECTpki<pki_key>("SELECT item from sm9_keys WHERE key_type IN (?, ?)",
                                       QList<QVariant>() << QVariant(EVP_PKEY_SM9_SIGN) 
                                                        << QVariant(EVP_PKEY_SM9_ENC));
}

void db_sm9::remFromCont(const QModelIndex &idx)
{
    db_base::remFromCont(idx);
    XSqlQuery q;

    QList<pki_x509super*> items = Store.sqlSELECTpki<pki_x509super>(
        "SELECT item FROM x509super WHERE pkey is NULL");
    foreach(pki_x509super *x509s, items) {
        x509s->setRefKey(NULL);
    }
}

void db_sm9::inToCont(pki_base *pki)
{
    db_base::inToCont(pki);
    pki_key *key = static_cast<pki_key*>(pki);
    
    // 只处理SM9密钥
    if (key->getKeyType() != EVP_PKEY_SM9_SIGN && 
        key->getKeyType() != EVP_PKEY_SM9_ENC) {
        return;
    }
    
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

pki_base* db_sm9::insert(pki_base *item)
{
    pki_key *lkey = dynamic_cast<pki_key *>(item);
    pki_key *oldkey;
    pki_evp *evp = dynamic_cast<pki_evp*>(lkey);
    
    // 只处理SM9密钥
    if (lkey && (lkey->getKeyType() != EVP_PKEY_SM9_SIGN && 
                lkey->getKeyType() != EVP_PKEY_SM9_ENC)) {
        qDebug() << "Ignoring non-SM9 key in db_sm9::insert";
        return NULL;
    }

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

pki_key *db_sm9::newSM9Key(const keyjob &job, const QString &name)
{
    // 检查是否是SM9密钥
    if (!job.ktype.isSM9()) {
        XCA_WARN(tr("Not a SM9 key type"));
        return NULL;
    }
    
    qDebug() << "Starting SM9 key generation with parameters:";
    qDebug() << "  SM9 Type:" << job.sm9Type;
    qDebug() << "  User ID:" << job.userId;
    qDebug() << "  User Password:" << job.idKeyPass;
    qDebug() << "  Name:" << name;
    pki_key *identkey = NULL;
    
    // 创建job的非const副本，以便可以修改
    keyjob jobCopy = job;

    // 检查必要参数
    if (jobCopy.sm9Type.isEmpty() || jobCopy.userId.isEmpty() || jobCopy.idKeyPass.isEmpty()) {
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
               << appDir + "/../xca-ABE/misc/sm9keygen.sh"     // 项目目录下的misc
               << "/usr/share/xca/misc/sm9keygen.sh"           // Linux系统标准位置
               << "/usr/local/share/xca/misc/sm9keygen.sh"     // Linux本地安装位置
               << "misc/sm9keygen.sh";                         // 相对于工作目录
    
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
    
    qDebug() << "Created temporary directory:" << tempDir;

    //
    try {
            identkey= new pki_evp(name);
        
            // 构建脚本参数 - 按照sm9keygen.sh脚本格式
            QStringList args;
            
            // 添加参数（位置参数格式：<alg> <user_id> <outpass>）
            qDebug() << "Setting SM9 type parameter:" << jobCopy.sm9Type;
            
            // 确保sm9Type值符合脚本要求
            if (jobCopy.sm9Type != "sm9sign" && jobCopy.sm9Type != "sm9encrypt") {
                qDebug() << "Invalid SM9 type:" << jobCopy.sm9Type << ", trying to derive from key type";
                if (jobCopy.ktype.type == EVP_PKEY_SM9_SIGN) {
                    jobCopy.sm9Type = "sm9sign";
                } else if (jobCopy.ktype.type == EVP_PKEY_SM9_ENC) {
                    jobCopy.sm9Type = "sm9encrypt";
                } else {
                    qDebug() << "Unable to determine valid SM9 type from key type:" << jobCopy.ktype.type;
                    QMessageBox::warning(NULL, XCA_TITLE, tr("Invalid SM9 type"));
                    return NULL;
                }
                qDebug() << "Derived SM9 type:" << jobCopy.sm9Type;
            }
            
            args << jobCopy.sm9Type;
            
            // 添加用户ID参数
            args << jobCopy.userId;
            
            // 添加密码参数
            args << jobCopy.idKeyPass;
            
            // 设置用户密钥输出路径（如果脚本支持指定输出文件）
            QString userKeyPath = tempDir + "/user_key.pem";
            if (QFile::exists(userKeyPath)) {
                QFile::remove(userKeyPath);
            }
            
            // 输出完整的命令行参数
            qDebug() << "Full command arguments:" << args.join(" ");
            
            // 执行脚本命令
            QProcess process;
            process.setProcessChannelMode(QProcess::MergedChannels); // 合并标准输出和错误输出
            process.start("bash", QStringList() << scriptPath << args);
            
            if (!process.waitForStarted(5000)) {
                qDebug() << "Error: Failed to start SM9 script";
                QMessageBox::warning(NULL, XCA_TITLE, 
                    tr("SM9 key generation process failed to start"));
                QDir(tempDir).removeRecursively();
                return NULL;
            }
            
            if (!process.waitForFinished(30000)) {
                process.kill();
                qDebug() << "Error: SM9 script execution timeout";
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
            
            // 确定生成的密钥文件名
            QString generatedFile;
            if (jobCopy.sm9Type == "sm9sign") {
                generatedFile = QString("sm9sign_%1.pem").arg(jobCopy.userId);
            } else if (jobCopy.sm9Type == "sm9encrypt") {
                generatedFile = QString("sm9enc_%1.pem").arg(jobCopy.userId);
            } else {
                qDebug() << "Unknown SM9 type:" << jobCopy.sm9Type;
                QMessageBox::warning(NULL, XCA_TITLE, tr("Unknown SM9 type"));
                QDir(tempDir).removeRecursively();
                return NULL;
            }
            
            // 检查在当前目录和其他可能位置
            QStringList possibleLocations;
            possibleLocations << generatedFile
                             << QDir::currentPath() + "/" + generatedFile
                             << QCoreApplication::applicationDirPath() + "/" + generatedFile
                             << QDir::currentPath() + "/sm9_keygen/" + generatedFile
                             << QCoreApplication::applicationDirPath() + "/sm9_keygen/" + generatedFile
                             << QCoreApplication::applicationDirPath() + "/misc/sm9_keygen/" + generatedFile
                             << QCoreApplication::applicationDirPath() + "/../misc/sm9_keygen/" + generatedFile;
            
            bool fileCopied = false;
            foreach (const QString &srcPath, possibleLocations) {
                qDebug() << "Checking for file at:" << srcPath;
                if (QFile::exists(srcPath)) {
                    // 如果目标文件已存在，先删除
                    if (QFile::exists(userKeyPath)) {
                        QFile::remove(userKeyPath);
                    }
                    
                    // 尝试复制文件
                    if (QFile::copy(srcPath, userKeyPath)) {
                        qDebug() << "Successfully copied key file from" << srcPath << "to" << userKeyPath;
                        fileCopied = true;
                        break;
                    } else {
                        qDebug() << "Failed to copy file from" << srcPath << "to" << userKeyPath;
                    }
                }
            }
            
            // 如果没有找到或复制文件
            if (!fileCopied) {
                qDebug() << "Generated file not found in any expected location";
                qDebug() << "Current directory:" << QDir::currentPath();
                qDebug() << "Files in current directory:" << QDir::current().entryList(QDir::Files);
                
                // 尝试在脚本执行目录查找文件
                QString appDir = QCoreApplication::applicationDirPath();
                qDebug() << "Application directory:" << appDir;
                qDebug() << "Files in application directory:" 
                        << QDir(appDir).entryList(QDir::Files);
            }
            
            // 检查文件是否存在
            if (!QFile::exists(userKeyPath)) {
                qDebug() << "Error: User key file not found: " << userKeyPath;
                qDebug() << "Files in temp directory:" << QDir(tempDir).entryList(QDir::Files);
                
                QMessageBox::warning(NULL, XCA_TITLE, 
                    tr("Generated key file not found"));
                QDir(tempDir).removeRecursively();
                return NULL;
            }
            qDebug() << "SM9 key generation successful";
            
            // 将生成的密钥文件导入到数据库
            try {
                qDebug() << "Importing key from:" << userKeyPath;
                
                // 导入用户密钥
                BIO *bio_user = BIO_new_file(userKeyPath.toUtf8().constData(), "r");
                if (!bio_user) {
                    qDebug() << "Error: Cannot open user key file";
                    QMessageBox::warning(NULL, XCA_TITLE, tr("Cannot open user key file"));
                    QDir(tempDir).removeRecursively();
                    delete identkey;
                    return NULL;
                }
                
                // 将密钥内容导入到刚创建的pki_evp对象中
                identkey->fromPEM_BIO(bio_user, jobCopy.idKeyPass.toUtf8().constData());
                BIO_free(bio_user);
                
                // 设置密钥类型和来源属性
                identkey->pkiSource = generated;
                
                if (identkey->getIntName().isEmpty())
                    identkey->autoIntName(name);
                
                // 插入到数据库
                identkey = dynamic_cast<pki_key*>(insert(identkey));
                
                // 删除临时文件
                QDir(tempDir).removeRecursively();
                
                // 通知密钥生成完成
                if (identkey) {
                    qDebug() << "SM9 key successfully imported into database";
                    emit keyDone(identkey);
                    createSuccess(identkey);
                }
            } catch (errorEx &err) {
                qDebug() << "Error: Failed to import generated key:" << err.getString();
                QMessageBox::warning(NULL, XCA_TITLE, 
                               tr("Failed to import generated key: %1").arg(err.getString()));
                QDir(tempDir).removeRecursively();
                delete identkey;
                identkey = NULL;
            }

    } catch (errorEx &err) {
        delete identkey;
        identkey = NULL;
        XCA_ERROR(err);
    }
    return identkey;
}

int db_sm9::exportFlags(const QModelIndex &index) const
{
    int disable_flags = 0;

    pki_key *key = fromIndex<pki_key>(index);

    if (!index.isValid() || !key)
        return 0;

    int keytype = key->getKeyType();
    
    // 检查是否为SM9密钥类型
    if (keytype != EVP_PKEY_SM9_SIGN && keytype != EVP_PKEY_SM9_ENC)
        disable_flags |= F_PVK | F_TRADITION;
        
    if (key->isPubKey() || key->isToken())
        disable_flags |= F_PRIVATE;
        
    disable_flags |= F_JWK | F_SSH2;

    return disable_flags;
}

void db_sm9::exportItem(const QModelIndex &index, const pki_export *xport,
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
    else
        db_base::exportItem(index, xport, file);
}

void db_sm9::resetPKI(pki_base *pki, QString name)
{
    if (name.isEmpty())
        name = pki->getIntName();
    else
        pki->setIntName(name);
    deletePKI(index(pki));
    pki->getSqlItemId();
    insertPKI(pki);
}

void db_sm9::setOwnPass(const QModelIndex &index, pki_key::passType type) {
    pki_key *key = fromIndex<pki_key>(index);
    if (key) {
        pki_evp *evp = dynamic_cast<pki_evp *>(key);
        if (evp) {
            evp->setOwnPass(type);
        }
    }
}
