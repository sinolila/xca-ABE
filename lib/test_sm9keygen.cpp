#include <QTest>
#include <QCoreApplication>
#include <QProcess>
#include <QFile>
#include <QDir>
#include <QDebug>
#include <QStandardPaths>

#include "db_key.h"
#include "pki_key.h"
#include "pki_evp.h"
#include "XcaWarningCore.h"
#include "PwDialogCore.h"

class TestSM9KeyGen : public QObject
{
    Q_OBJECT

private slots:
    void initTestCase();
    void cleanupTestCase();
    void testScriptExists();
    void testKeyGeneration();
    void testInvalidParameters();

private:
    db_key *key_db;
    QString testDir;
    QString scriptPath;
    bool setupEnvironment();
};

bool TestSM9KeyGen::setupEnvironment()
{
    // ���GmSSL�Ƿ�װ
    QProcess process;
    process.start("which", QStringList() << "gmssl");
    if (!process.waitForFinished() || process.exitCode() != 0) {
        qWarning() << "GmSSL not found in PATH";
        return false;
    }

    // ���ýű�·��
    QStringList possiblePaths = {
        QCoreApplication::applicationDirPath() + "/misc/sm9keygen.sh",
        QStandardPaths::locate(QStandardPaths::GenericDataLocation, "xca/misc/sm9keygen.sh"),
        "/usr/share/xca/misc/sm9keygen.sh",
        "/usr/local/share/xca/misc/sm9keygen.sh"
    };

    for (const QString &path : possiblePaths) {
        if (QFile::exists(path)) {
            scriptPath = path;
            QFile script(scriptPath);
            if (!(script.permissions() & QFile::ExeUser)) {
                script.setPermissions(script.permissions() | QFile::ExeUser);
            }
            return true;
        }
    }

    qWarning() << "sm9keygen.sh not found in any of the expected locations";
    return false;
}

void TestSM9KeyGen::initTestCase()
{
    // ��������Ŀ¼
    testDir = QDir::tempPath() + "/xca_sm9_test";
    QDir().mkpath(testDir);
    
    // ���û���
    if (!setupEnvironment()) {
        QSKIP("Required environment not set up properly");
    }
    
    // ��ʼ�����ݿ�
    key_db = new db_key();
}

void TestSM9KeyGen::cleanupTestCase()
{
    // �������Ŀ¼
    QDir(testDir).removeRecursively();
    delete key_db;
}

void TestSM9KeyGen::testScriptExists()
{
    QVERIFY2(QFile::exists(scriptPath), "SM9 key generation script not found");
    QFile script(scriptPath);
    QVERIFY2(script.permissions() & QFile::ExeUser, "Script is not executable");
}

void TestSM9KeyGen::testKeyGeneration()
{
    // ׼�����Բ���
    keyjob job;
    job.sm9Type = "sm9sign";
    job.userId = "test_user";
    job.masterKeyPass = "test_password";
    
    // ������Կ���ɷ���
    pki_key *key = key_db->newIdentKey(job, "Test SM9 Key");
    
    // ��֤��Կ�Ƿ�ɹ�����
    QVERIFY2(key != nullptr, "Failed to generate SM9 key");
    
    // ��֤��Կ����
    QVERIFY2(key->isPrivKey(), "Generated key is not a private key");
    
    // ��֤��Կ�ļ��Ƿ����
    QString keyFile = testDir + "/sm9sign_test_user.pem";
    QVERIFY2(QFile::exists(keyFile), "Generated key file not found");
}

void TestSM9KeyGen::testInvalidParameters()
{
    // ������Ч���㷨����
    keyjob job;
    job.sm9Type = "invalid_alg";
    job.userId = "test_user";
    job.masterKeyPass = "test_password";
    
    pki_key *key = key_db->newIdentKey(job, "Invalid Algorithm");
    QVERIFY2(key == nullptr, "Should fail with invalid algorithm type");
    
    // ���Կյ��û�ID
    job.sm9Type = "sm9sign";
    job.userId = "";
    key = key_db->newIdentKey(job, "Empty User ID");
    QVERIFY2(key == nullptr, "Should fail with empty user ID");
}

QTEST_MAIN(TestSM9KeyGen)
#include "test_sm9keygen.moc" 