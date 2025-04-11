/**
 * 简化版SM9密钥生成测试程序
 * 包含两种测试方式：
 * 1. 直接调用脚本测试（已注释）
 * 2. 通过db_key接口测试
 */

#include <QCoreApplication>
#include <QProcess>
#include <QDir>
#include <QDebug>
#include <QDateTime>
#include <QFile>

int main(int argc, char *argv[])
{
    QCoreApplication app(argc, argv);
    
    qDebug() << "开始测试SM9密钥生成脚本...";
    
    // ===================== 方式一：直接调用脚本（已注释） =====================

    // 1. 检查GmSSL是否可用
    {
        QProcess process;
        process.start("gmssl", QStringList() << "version");
        if (!process.waitForStarted(3000) || !process.waitForFinished(3000)) {
            qDebug() << "错误: GmSSL不可用";
            qDebug() << "请确保GmSSL已安装并添加到PATH中";
            return 1;
        }
        QString gmssl_version = QString::fromUtf8(process.readAll()).trimmed();
        qDebug() << "GmSSL版本:" << gmssl_version;
    }
    
    // 2. 查找sm9keygen.sh脚本
    QStringList searchPaths;
    QString appDir = QCoreApplication::applicationDirPath();
    
    searchPaths << appDir + "/misc/sm9keygen.sh"
                 << appDir + "../xca-ABE/misc/sm9keygen.sh"
               << appDir + "/../misc/sm9keygen.sh"
               << appDir + "/../share/xca/misc/sm9keygen.sh"
               << "/usr/share/xca/misc/sm9keygen.sh"
               << "/usr/local/share/xca/misc/sm9keygen.sh";
    
    QString scriptPath;
    foreach (const QString &path, searchPaths) {
        if (QFile::exists(path)) {
            scriptPath = path;
            qDebug() << "找到SM9脚本:" << scriptPath;
            break;
        }
    }
    
    if (scriptPath.isEmpty()) {
        qDebug() << "错误: 未找到SM9密钥生成脚本";
        return 1;
    }
    
    // 3. 创建临时目录
    QString tempDir = QDir::tempPath() + "/sm9_test_" + 
                     QString::number(QDateTime::currentMSecsSinceEpoch());
    QDir().mkpath(tempDir);
    
    // 4. 执行脚本生成密钥
    QString sm9Type = "sm9sign";
    QString userId = "testuser";
    QString masterKeyPass = "test123";
    
    QStringList args;
    args << sm9Type << userId << masterKeyPass;
    
    QProcess process;
    process.setWorkingDirectory(tempDir);
    process.start("bash", QStringList() << scriptPath << args);
    
    if (!process.waitForStarted(5000)) {
        qDebug() << "错误: 脚本启动失败";
        QDir(tempDir).removeRecursively();
        return 1;
    }
    
    if (!process.waitForFinished(30000)) {
        process.kill();
        qDebug() << "错误: 脚本执行超时";
        QDir(tempDir).removeRecursively();
        return 1;
    }
    
    QString output = QString::fromUtf8(process.readAll());
    qDebug() << "脚本输出:" << output;
    
    if (process.exitCode() != 0) {
        qDebug() << "错误: 脚本执行失败";
        QDir(tempDir).removeRecursively();
        return 1;
    }
    
    // 5. 验证生成的密钥文件
    QString keyFile = tempDir + "/" + sm9Type + "_" + userId + ".pem";
    if (QFile::exists(keyFile)) {
        qDebug() << "成功: 密钥文件已生成:" << keyFile;
        
        // 显示文件内容预览
        QFile file(keyFile);
        if (file.open(QIODevice::ReadOnly | QIODevice::Text)) {
            QByteArray content = file.readAll();
            qDebug() << "文件内容预览 (前100字节):" << content.left(100);
            file.close();
        }
    } else {
        qDebug() << "错误: 未找到生成的密钥文件";
        qDebug() << "临时目录中的文件:" << QDir(tempDir).entryList();
        QDir(tempDir).removeRecursively();
        return 1;
    }
    
    // 6. 清理
    QDir(tempDir).removeRecursively();
}
    
    // ===================== 方式二：通过db_key接口测试 =====================
    // 创建db_key实例
//     db_key *keydb = new db_key();
    
//     // 创建keyjob对象并设置参数
//     keyjob job;
//     job.sm9Type = "sm9sign";      // 设置SM9类型为签名
//     job.userId = "testuser";       // 设置测试用户ID
//     job.idKeyPass = "test123";     // 设置密码
    
//     // 设置密钥类型
//     // job.ktype.type = EVP_PKEY_SM9;  // 使用SM9密钥类型
//     // job.ktype.name = "SM9";
    
//     qDebug() << "密钥生成参数:";
//     qDebug() << "  SM9类型:" << job.sm9Type;
//     qDebug() << "  用户ID:" << job.userId;
//     qDebug() << "  密码:" << job.idKeyPass;
//     qDebug() << "  密钥类型:" << job.ktype.name;
    
//     // 调用newIdentKey生成密钥
//     pki_key *key = keydb->newIdentKey(job, "TestSM9Key");
    
//     if (key) {
//         qDebug() << "密钥生成成功";
//         delete key;
//     } else {
//         qDebug() << "密钥生成失败或处于测试模式";
//     }
    
//     delete keydb;
//     qDebug() << "测试完成";
    
//     return 0;}

