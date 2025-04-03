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

	// ���� SM9 ��ص� UI
	setupSM9UI();

	// ������Կ���ȿؼ�
	keyLength->setVisible(false);
	keySizeLabel->setVisible(false);
	
	// ��������ѡ���
	curveBox->setVisible(false);
	curveLabel->setVisible(false);

	// ��� IBC �� SM9 ����
	populateIBCParameters();
	
	// ��� IBC �� SM9 ����
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
			// ��� IBC �� SM9 ��ص� Token ����
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
	
	// ���û��ѡ����һ��Ĭ�ϵ�
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
	
	// �����źŲ�
	connect(keyType, SIGNAL(currentIndexChanged(int)), this, SLOT(on_keyType_currentIndexChanged(int)));
	
	buttonBox->button(QDialogButtonBox::Ok)->setText(tr("Create"));
	
	// ��ʼ��UI��ʾ
	updateSM9WidgetVisibility();
	
	// ���GmSSL�Ƿ�װ
	if (isSM9Selected() && !checkGmSSLInstalled()) {
		QMessageBox::warning(this, XCA_TITLE, 
			tr("GmSSL tool not detected. Please ensure GmSSL is installed and added to PATH environment variable, otherwise SM9 keys cannot be generated."));
	}
}

void NewIdentKey::setupSM9UI()
{
	// ���� SM9 ��ص� UI Ԫ��
	sm9Widget = new QWidget(this);
	QGridLayout *gridLayout2 = new QGridLayout(sm9Widget);
	gridLayout2->setContentsMargins(0, 0, 0, 0);  // ���ٱ߾��Ա������Ϸ���ǩ�Ķ���
	
	// ������ǩ�������
	masterKeyPassLabel = new QLabel(tr("Master Key Password:"), sm9Widget);
	masterKeyPass = new QLineEdit(sm9Widget);
	masterKeyPass->setEchoMode(QLineEdit::Password);
	
	idLabel = new QLabel(tr("User ID:"), sm9Widget);
	idInput = new QLineEdit(sm9Widget);
	
	// ��ӿؼ������񲼾֣�ȷ����ǩ�����һ�У���������ұ�һ��
	// ����UI�ļ��еĲ��ַ�ʽһ��
	gridLayout2->addWidget(masterKeyPassLabel, 0, 0);
	gridLayout2->addWidget(masterKeyPass, 0, 1);
	gridLayout2->addWidget(idLabel, 1, 0);
	gridLayout2->addWidget(idInput, 1, 1);
	
	// ���õ�1�У�����������У�����չ
	gridLayout2->setColumnStretch(1, 1);
	
	// �� SM9 �ؼ���ӵ�������
	gridLayout->addWidget(sm9Widget, 6, 0, 1, 3);
	
	// Ĭ������ SM9 �ؼ�
	sm9Widget->setVisible(false);
	
	// �������б�ǩ�Ķ��뷽ʽ
	QList<QLabel*> labels = findChildren<QLabel*>();
	foreach (QLabel* label, labels) {
		if (label != image && label->objectName() != "hintLabel") {
			label->setAlignment(Qt::AlignLeft | Qt::AlignVCenter);
		}
	}
}

// ��� SM9 ����������ѡ���
void NewIdentKey::populateIBCParameters()
{
	curveBox->clear();
	
	// ��� IBC ���õĲ���
	// curveBox->addItem("SM9_256", "SM9_256");
	// curveBox->addItem("SM9_sign", "sm9sign");
	// curveBox->addItem("SM9_encrypt", "sm9encrypt");
	// ����Ӹ��� IBC ����
	
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
	// ��鵱ǰѡ����Ƿ�Ϊ SM9 ����
	bool sm9Selected = isSM9Selected();
	
	// ��ʾ/���� SM9 ��ؿؼ�
	sm9Widget->setVisible(sm9Selected);
	
	// ��ʾ/���ر�׼�ؼ�
	keyLength->setVisible(!sm9Selected);
	keySizeLabel->setVisible(!sm9Selected);
	
	// �����Ի����С
	adjustSize();
}

void NewIdentKey::on_keyType_currentIndexChanged(int idx)
{
	if (idx < 0)
		return;
	
	QVariant q = keyType->itemData(idx);
	keyListItem currentItem = q.value<keyListItem>();
	
	// ���� UI ��ʾ
	updateSM9WidgetVisibility();
	
	// ����������Կ���͵�ԭ�д���...
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
	
	// ���� SM9 ��ز���
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
	
	// ���� SM9 ��Կ����
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
	
	// ��������������Կ���ɵ�ԭ�д���...
	QDialog::accept();
}

bool NewIdentKey::generateSM9Key(const QString &keyName, QString &errorMsg)
{
	// ��֤����
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
	
	// ֱ�Ӵӵ�ǰѡ�����Կ���ͻ�ȡSM9����
	int idx = keyType->currentIndex();
	QVariant q = keyType->itemData(idx);
	keyListItem currentItem = q.value<keyListItem>();
	
	// ������Կ����ȷ����ǩ�����Ǽ���
	QString sm9Type = (currentItem.ktype.type == EVP_PKEY_SM9_SIGN) ? "sign" : "encrypt";
	
	// ���ҽű� - ��Ҫ�޸Ĵ˲�������ȷ������ĿĿ¼�еĽű�
	QStringList searchPaths;
	
	// ��ӿ��ܵĽű�·��
	QString appDir = QCoreApplication::applicationDirPath();
	searchPaths << appDir + "/misc/sm9keygen.sh"               // Ӧ�ó���Ŀ¼�µ�misc
			   << appDir + "/../misc/sm9keygen.sh"             // �ϼ�Ŀ¼��misc
			   << appDir + "/../share/xca/misc/sm9keygen.sh"   // ��׼��װλ��
			   << "../misc/sm9keygen.sh"                       // ����ڹ���Ŀ¼
			   << "misc/sm9keygen.sh";                         // ��ĿĿ¼
	
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
	
	// ���ýű�ִ��Ȩ��
	QProcess::execute("chmod", QStringList() << "+x" << scriptPath);
	
	// ������ʱĿ¼
	QString tempDir = QDir::tempPath() + "/xca_sm9_" + 
					 QString::number(QDateTime::currentMSecsSinceEpoch());
	QDir().mkpath(tempDir);
	
	// ������ʱ����ļ�·��
	QString masterKeyPath = tempDir + "/sm9_master.pem";
	QString userKeyPath = tempDir + "/sm9_user.pem";
	
	// ���������е��� - ��������Կ
	QStringList setupArgs;
	setupArgs << scriptPath
			  << "-setup"
			  << "-type" << sm9Type  // ʹ�ô���Կ����ȷ����SM9����
			  << "-pass" << masterKeyPassword
			  << "-out" << masterKeyPath;
	
	// ���������Ϣ���������
	qDebug() << "SM9 Key Generation command: " << "bash" << setupArgs.join(" ");
	
	// ִ����������Կ����
	QProcess setupProcess;
	setupProcess.setProcessChannelMode(QProcess::MergedChannels); // �ϲ�����������ڵ���
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
	
	// �������ִ�н��
	if (setupProcess.exitCode() != 0) {
		QString output = QString::fromUtf8(setupProcess.readAll());
		qDebug() << "SM9 master key generation error:";
		qDebug() << output;
		errorMsg = tr("SM9 master key generation failed:\n%1").arg(output);
		QDir(tempDir).removeRecursively();
		return false;
	}
	
	// �������Կ�ļ��Ƿ����
	if (!QFile::exists(masterKeyPath)) {
		errorMsg = tr("Generated SM9 master key file not found");
		QDir(tempDir).removeRecursively();
		return false;
	}
	
	// ���������е��� - �����û���Կ
	QStringList keygenArgs;
	keygenArgs << scriptPath
			   << "-type" << sm9Type  // ʹ�ô���Կ����ȷ����SM9����
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
	
	// �������ִ�н��
	if (keygenProcess.exitCode() != 0) {
		QString stdErr = QString::fromUtf8(keygenProcess.readAllStandardError());
		QString stdOut = QString::fromUtf8(keygenProcess.readAllStandardOutput());
		errorMsg = tr("SM9 user key generation failed:\n%1\n%2").arg(stdErr).arg(stdOut);
		QDir(tempDir).removeRecursively();
		return false;
	}
	
	// ����û���Կ�ļ��Ƿ����
	if (!QFile::exists(userKeyPath)) {
		errorMsg = tr("Generated SM9 user key file not found");
		QDir(tempDir).removeRecursively();
		return false;
	}
	
	// �����ɵ���Կ���� XCA ���ݿ�
	try {
		// ��������Կ
		BIO *bio_master = BIO_new_file(masterKeyPath.toUtf8().constData(), "r");
		if (!bio_master) {
			errorMsg = tr("Unable to open master key file");
			QDir(tempDir).removeRecursively();
			return false;
		}
		pki_evp *masterKey = new pki_evp(keyName + "_����Կ");
		masterKey->fromPEM_BIO(bio_master, masterKeyPassword.toUtf8().constData());
		BIO_free(bio_master);
		Database.model<db_key>()->insert(masterKey);
		
		// �����û���Կ
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
		
		// ɾ����ʱ�ļ�
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


