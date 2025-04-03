/* vi: set sw=4 ts=4:
 *
 * Copyright (C) 2001 - 2020 Christian Hohnstaedt.
 *
 * All rights reserved.
 */


#include "NewIdentKey.h"
#include "MainWindow.h"
#include "Help.h"
#include "lib/pki_evp.h"
#include "lib/pki_key.h"
#include "lib/pkcs11.h"
#include "distname.h"
#include "clicklabel.h"
#include "ItemCombo.h"
#include <QLabel>
#include <QPushButton>
#include <QLineEdit>
#include <QStringList>
#include <QMessageBox>
#include <QProcess>
#include <QTemporaryFile>
#include <QFile>
#include <QFileDialog>
#include <QVBoxLayout>
#include <QCoreApplication>
#include <openssl/bio.h>

class keyListItem
{
    public:
	bool card;
	keytype ktype;
	QString printname;
	slotid slot;
	unsigned minKeySize;
	unsigned maxKeySize;
	unsigned long ec_flags;

	keyListItem(pkcs11 *p11, slotid nslot, CK_MECHANISM_TYPE m)
	{
		slot = nslot;
		CK_MECHANISM_INFO mechinfo;
		p11->mechanismInfo(slot, m, &mechinfo);

		minKeySize = mechinfo.ulMinKeySize;
		maxKeySize = mechinfo.ulMaxKeySize;
		if (maxKeySize == 0) {
			/* Fallback for libraries not
			 * filling in the maxKeySize */
			maxKeySize = INT_MAX;
		}
		ktype = keytype::byMech(m);
		tkInfo ti = p11->tokenInfo(slot);
		
		printname = QString("%1 #%2 (%3 Key)").
			arg(ti.label()).arg(ti.serial()).
			arg(ktype.name);
		card = true;
	}
	keyListItem(const keytype &t = keytype())
		: ktype(t)
	{
		printname = ktype.name;
		card = false;
		slot = slotid();
		minKeySize = 0;
		maxKeySize = INT_MAX;
		ec_flags = 0;
	}
	int type() const
	{
		return ktype.type;
	}
};

Q_DECLARE_METATYPE(keyListItem);

NewIdentKey::NewIdentKey(QWidget *parent, const QString &name)
	:QDialog(parent ? parent : mainwin)
{
	slotidList p11_slots;
	QList<keyListItem> keytypes;

	setupUi(this);
	setWindowTitle(XCA_TITLE);
	image->setPixmap(QPixmap(":keyImg"));
	mainwin->helpdlg->register_ctxhelp_button(this, "keygen");

	if (!name.isEmpty())
		keyDesc->setText(name);

	// 设置 SM9 相关的 UI
	setupSM9UI();

	// 隐藏密钥长度控件
	keyLength->setVisible(false);
	keySizeLabel->setVisible(false);
	
	// 保留曲线选择框
	curveBox->setVisible(false);
	curveLabel->setVisible(false);

	// 添加 IBC 和 SM9 参数
	populateIBCParameters();
	
	// 添加 IBC 和 SM9 类型
	foreach (const keytype t, keytype::types()) {
		if (t.isIBC() || t.isSM9()) {
			keytypes << keyListItem(t);
		}
	}

	keyDesc->setFocus();
	
	if (pkcs11::libraries.loaded()) try {
		pkcs11 p11;
		p11_slots = p11.getSlotList();

		foreach(slotid slot, p11_slots) {
			QList<CK_MECHANISM_TYPE> ml = p11.mechanismList(slot);
			// 添加 IBC 和 SM9 相关的 Token 机制
			foreach(keytype t, keytype::types()) {
				if ((t.isIBC() || t.isSM9()) && ml.contains(t.mech))
					keytypes << keyListItem(&p11, slot, t.mech);
			}
		}
	} catch (errorEx &) {
		p11_slots.clear();
	}
	
	for (int i=0; i<keytypes.count(); i++) {
		QVariant q;
		q.setValue(keytypes[i]);
		keyType->addItem(keytypes[i].printname, q);
	}
	
	// 如果没有选项，添加一个默认的
	if (keyType->count() == 0) {
		foreach (const keytype t, keytype::types()) {
			if (t.isIBC() || t.isSM9()) {
				QVariant q;
				keyListItem item(t);
				q.setValue(item);
				keyType->addItem(item.printname, q);
				break;
			}
		}
	}
	
	// 连接信号槽
	connect(keyType, SIGNAL(currentIndexChanged(int)), this, SLOT(on_keyType_currentIndexChanged(int)));
	
	buttonBox->button(QDialogButtonBox::Ok)->setText(tr("Create"));
	
	// 初始化UI显示
	updateSM9WidgetVisibility();
	
	// 检查GmSSL是否安装
	if (isSM9Selected() && !checkGmSSLInstalled()) {
		QMessageBox::warning(this, XCA_TITLE, 
			tr("GmSSL tool not detected. Please ensure GmSSL is installed and added to PATH environment variable, otherwise SM9 keys cannot be generated."));
	}
}

void NewIdentKey::setupSM9UI()
{
	// 创建 SM9 相关的 UI 元素
	sm9Widget = new QWidget(this);
	QGridLayout *gridLayout2 = new QGridLayout(sm9Widget);
	gridLayout2->setContentsMargins(0, 0, 0, 0);  // 减少边距以保持与上方标签的对齐
	
	// 创建标签和输入框
	masterKeyPassLabel = new QLabel(tr("Master Key Password:"), sm9Widget);
	masterKeyPass = new QLineEdit(sm9Widget);
	masterKeyPass->setEchoMode(QLineEdit::Password);
	
	idLabel = new QLabel(tr("User ID:"), sm9Widget);
	idInput = new QLineEdit(sm9Widget);
	
	// 添加控件到网格布局，确保标签在左边一列，输入框在右边一列
	// 这与UI文件中的布局方式一致
	gridLayout2->addWidget(masterKeyPassLabel, 0, 0);
	gridLayout2->addWidget(masterKeyPass, 0, 1);
	gridLayout2->addWidget(idLabel, 1, 0);
	gridLayout2->addWidget(idInput, 1, 1);
	
	// 设置第1列（输入框所在列）可伸展
	gridLayout2->setColumnStretch(1, 1);
	
	// 将 SM9 控件添加到主布局
	gridLayout->addWidget(sm9Widget, 6, 0, 1, 3);
	
	// 默认隐藏 SM9 控件
	sm9Widget->setVisible(false);
	
	// 调整所有标签的对齐方式
	QList<QLabel*> labels = findChildren<QLabel*>();
	foreach (QLabel* label, labels) {
		if (label != image && label->objectName() != "hintLabel") {
			label->setAlignment(Qt::AlignLeft | Qt::AlignVCenter);
		}
	}
}

// 添加 SM9 参数到参数选择框
void NewIdentKey::populateIBCParameters()
{
	curveBox->clear();
	
	// 添加 IBC 可用的参数
	// curveBox->addItem("SM9_256", "SM9_256");
	// curveBox->addItem("SM9_sign", "sm9sign");
	// curveBox->addItem("SM9_encrypt", "sm9encrypt");
	// 可添加更多 IBC 参数
	
	curveBox->setCurrentIndex(0);
}

bool NewIdentKey::isSM9Selected()
{
	int idx = keyType->currentIndex();
	if (idx < 0)
		return false;
	
	QVariant q = keyType->itemData(idx);
	if (!q.isValid())
		return false;
	
	keyListItem item = q.value<keyListItem>();
	return item.ktype.isSM9();
}

void NewIdentKey::updateSM9WidgetVisibility()
{
	// 检查当前选择的是否为 SM9 类型
	bool sm9Selected = isSM9Selected();
	
	// 显示/隐藏 SM9 相关控件
	sm9Widget->setVisible(sm9Selected);
	
	// 显示/隐藏标准控件
	keyLength->setVisible(!sm9Selected);
	keySizeLabel->setVisible(!sm9Selected);
	
	// 调整对话框大小
	adjustSize();
}

void NewIdentKey::on_keyType_currentIndexChanged(int idx)
{
	if (idx < 0)
		return;
	
	QVariant q = keyType->itemData(idx);
	keyListItem currentItem = q.value<keyListItem>();
	
	// 更新 UI 显示
	updateSM9WidgetVisibility();
	
	// 处理其他密钥类型的原有代码...
}

keyjob NewIdentKey::getKeyJob() const
{
	keyjob job;
	keyListItem currentItem;
	int idx = keyType->currentIndex();
	QVariant q = keyType->itemData(idx);
	
	if (q.isValid())
		currentItem = q.value<keyListItem>();
	
	job.ktype = currentItem.ktype;
	
	// 设置 SM9 相关参数
	if (job.ktype.isSM9()) {
		job.masterKeyPass = masterKeyPass->text();
		job.userId = idInput->text();
	}
	
	return job;
}

void NewIdentKey::accept()
{
	QString name = keyDesc->text();
	if (name.isEmpty()) {
		QMessageBox::warning(this, XCA_TITLE, tr("Please enter key description"));
		return;
	}
	
	// 处理 SM9 密钥生成
	if (isSM9Selected()) {
		QString errorMsg;
		if (!generateSM9Key(name, errorMsg)) {
			QMessageBox::warning(this, XCA_TITLE, 
				tr("SM9 key generation failed: %1").arg(errorMsg));
			return;
		}
		
		QDialog::accept();
		return;
	}
	
	// 处理其他类型密钥生成的原有代码...
	QDialog::accept();
}

bool NewIdentKey::generateSM9Key(const QString &keyName, QString &errorMsg)
{
	// 验证输入
	QString masterKeyPassword = masterKeyPass->text();
	QString userId = idInput->text();
	
	if (masterKeyPassword.isEmpty()) {
		errorMsg = tr("Please enter master key password");
		return false;
	}
	
	if (userId.isEmpty()) {
		errorMsg = tr("Please enter user ID");
		return false;
	}
	
	// 直接从当前选择的密钥类型获取SM9类型
	int idx = keyType->currentIndex();
	QVariant q = keyType->itemData(idx);
	keyListItem currentItem = q.value<keyListItem>();
	
	// 根据密钥类型确定是签名还是加密
	QString sm9Type = (currentItem.ktype.type == EVP_PKEY_SM9_SIGN) ? "sign" : "encrypt";
	
	// 查找脚本 - 需要修改此部分以正确查找项目目录中的脚本
	QStringList searchPaths;
	
	// 添加可能的脚本路径
	QString appDir = QCoreApplication::applicationDirPath();
	searchPaths << appDir + "/misc/sm9keygen.sh"               // 应用程序目录下的misc
			   << appDir + "/../misc/sm9keygen.sh"             // 上级目录的misc
			   << appDir + "/../share/xca/misc/sm9keygen.sh"   // 标准安装位置
			   << "../misc/sm9keygen.sh"                       // 相对于工作目录
			   << "misc/sm9keygen.sh";                         // 项目目录
	
	QString scriptPath;
	foreach (const QString &path, searchPaths) {
		if (QFile::exists(path)) {
			scriptPath = path;
			break;
		}
	}
	
	if (scriptPath.isEmpty()) {
		errorMsg = tr("SM9 key generation script not found, please ensure correct installation");
		return false;
	}
	
	// 设置脚本执行权限
	QProcess::execute("chmod", QStringList() << "+x" << scriptPath);
	
	// 创建临时目录
	QString tempDir = QDir::tempPath() + "/xca_sm9_" + 
					 QString::number(QDateTime::currentMSecsSinceEpoch());
	QDir().mkpath(tempDir);
	
	// 创建临时输出文件路径
	QString masterKeyPath = tempDir + "/sm9_master.pem";
	QString userKeyPath = tempDir + "/sm9_user.pem";
	
	// 构建命令行调用 - 生成主密钥
	QStringList setupArgs;
	setupArgs << scriptPath
			  << "-setup"
			  << "-type" << sm9Type  // 使用从密钥类型确定的SM9类型
			  << "-pass" << masterKeyPassword
			  << "-out" << masterKeyPath;
	
	// 输出调试信息，帮助诊断
	qDebug() << "SM9 Key Generation command: " << "bash" << setupArgs.join(" ");
	
	// 执行生成主密钥命令
	QProcess setupProcess;
	setupProcess.setProcessChannelMode(QProcess::MergedChannels); // 合并输出流，便于调试
	setupProcess.start("/bin/bash", setupArgs);
	
	if (!setupProcess.waitForStarted(5000)) {
		errorMsg = tr("Unable to start SM9 key generation script for master key");
		QDir(tempDir).removeRecursively();
		return false;
	}
	
	if (!setupProcess.waitForFinished(30000)) {
		setupProcess.kill();
		errorMsg = tr("SM9 master key generation timeout");
		QDir(tempDir).removeRecursively();
		return false;
	}
	
	// 检查命令执行结果
	if (setupProcess.exitCode() != 0) {
		QString output = QString::fromUtf8(setupProcess.readAll());
		qDebug() << "SM9 master key generation error:";
		qDebug() << output;
		errorMsg = tr("SM9 master key generation failed:\n%1").arg(output);
		QDir(tempDir).removeRecursively();
		return false;
	}
	
	// 检查主密钥文件是否存在
	if (!QFile::exists(masterKeyPath)) {
		errorMsg = tr("Generated SM9 master key file not found");
		QDir(tempDir).removeRecursively();
		return false;
	}
	
	// 构建命令行调用 - 生成用户密钥
	QStringList keygenArgs;
	keygenArgs << scriptPath
			   << "-type" << sm9Type  // 使用从密钥类型确定的SM9类型
			   << "-master" << masterKeyPath
			   << "-pass" << masterKeyPassword
			   << "-id" << userId
			   << "-out" << userKeyPath;
	
	QProcess keygenProcess;
	keygenProcess.start("/bin/bash", keygenArgs);
	
	if (!keygenProcess.waitForStarted(5000)) {
		errorMsg = tr("Unable to start SM9 key generation script for user key");
		QDir(tempDir).removeRecursively();
		return false;
	}
	
	if (!keygenProcess.waitForFinished(30000)) {
		keygenProcess.kill();
		errorMsg = tr("SM9 user key generation timeout");
		QDir(tempDir).removeRecursively();
		return false;
	}
	
	// 检查命令执行结果
	if (keygenProcess.exitCode() != 0) {
		QString stdErr = QString::fromUtf8(keygenProcess.readAllStandardError());
		QString stdOut = QString::fromUtf8(keygenProcess.readAllStandardOutput());
		errorMsg = tr("SM9 user key generation failed:\n%1\n%2").arg(stdErr).arg(stdOut);
		QDir(tempDir).removeRecursively();
		return false;
	}
	
	// 检查用户密钥文件是否存在
	if (!QFile::exists(userKeyPath)) {
		errorMsg = tr("Generated SM9 user key file not found");
		QDir(tempDir).removeRecursively();
		return false;
	}
	
	// 将生成的密钥导入 XCA 数据库
	try {
		// 导入主密钥
		BIO *bio_master = BIO_new_file(masterKeyPath.toUtf8().constData(), "r");
		if (!bio_master) {
			errorMsg = tr("Unable to open master key file");
			QDir(tempDir).removeRecursively();
			return false;
		}
		pki_evp *masterKey = new pki_evp(keyName + "_主密钥");
		masterKey->fromPEM_BIO(bio_master, masterKeyPassword.toUtf8().constData());
		BIO_free(bio_master);
		Database.model<db_key>()->insert(masterKey);
		
		// 导入用户密钥
		BIO *bio_user = BIO_new_file(userKeyPath.toUtf8().constData(), "r");
		if (!bio_user) {
			errorMsg = tr("Unable to open user key file");
			QDir(tempDir).removeRecursively();
			return false;
		}
		pki_evp *userKey = new pki_evp(keyName);
		userKey->fromPEM_BIO(bio_user, masterKeyPassword.toUtf8().constData());
		BIO_free(bio_user);
		Database.model<db_key>()->insert(userKey);
		
		// 删除临时文件
		QDir(tempDir).removeRecursively();
		
		return true;
	} catch (errorEx &err) {
		errorMsg = tr("Unable to import generated key: %1").arg(err.getString());
		QDir(tempDir).removeRecursively();
		return false;
	}
}

bool NewIdentKey::checkGmSSLInstalled()
{
	QProcess process;
	process.start("gmssl", QStringList() << "version");
	
	if (!process.waitForStarted(3000)) {
		return false;
	}
	
	if (!process.waitForFinished(3000)) {
		process.kill();
		return false;
	}
	
	return process.exitCode() == 0;
}


