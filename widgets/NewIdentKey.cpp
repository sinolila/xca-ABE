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
	setWindowFlags(windowFlags() & ~Qt::WindowContextHelpButtonHint);

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
	
}

void NewIdentKey::setupSM9UI()
{
	// ���� SM9 ��ص� UI Ԫ��
	sm9Widget = new QWidget(this);
	QGridLayout *gridLayout2 = new QGridLayout(sm9Widget);
	gridLayout2->setContentsMargins(0, 0, 0, 0);  // ���ٱ߾��Ա������Ϸ���ǩ�Ķ���
	
	// ������ǩ�������
	idLabel = new QLabel(tr("User ID:"), sm9Widget);
	idInput = new QLineEdit(sm9Widget);
	
	masterKeyPassLabel = new QLabel(tr("User Password:"), sm9Widget);
	masterKeyPass = new QLineEdit(sm9Widget);
	masterKeyPass->setEchoMode(QLineEdit::Password);
	
	// ��ӿؼ������񲼾֣�ȷ����ǩ�����һ�У���������ұ�һ��
	// ����UI�ļ��еĲ��ַ�ʽһ��
	gridLayout2->addWidget(idLabel, 0, 0);
	gridLayout2->addWidget(idInput, 0, 1);
	gridLayout2->addWidget(masterKeyPassLabel, 1, 0);
	gridLayout2->addWidget(masterKeyPass, 1, 1);
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
		// ������Կ��������SM9����
		if (job.ktype.type == EVP_PKEY_SM9_SIGN) {
			job.sm9Type = "sm9sign";
		} else if (job.ktype.type == EVP_PKEY_SM9_ENC) {
			job.sm9Type = "sm9encrypt";
		}
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
	qDebug() << "Starting SM9 key generation...";
	qDebug() << "Key Name:" << keyName;
	
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
	
	// ��ȡSM9����
	int idx = keyType->currentIndex();
	QVariant q = keyType->itemData(idx);
	if (!q.isValid()) {
		errorMsg = tr("Invalid key type selected");
		return false;
	}
	
	keyListItem currentItem = q.value<keyListItem>();
	QString sm9Type = (currentItem.ktype.type == EVP_PKEY_SM9_SIGN) ? "sm9sign" : "sm9encrypt";
	
	// ����keyjob����
	keyjob job;
	job.ktype = currentItem.ktype;
	job.sm9Type = sm9Type;
	job.userId = userId;
	job.masterKeyPass = masterKeyPassword;
	
	// ����db_key��newIdentKey����������Կ
	pki_key *key = Database.model<db_key>()->newIdentKey(job, keyName);
	if (!key) {
		errorMsg = tr("Failed to generate SM9 key");
		return false;
	}
	
	return true;
}