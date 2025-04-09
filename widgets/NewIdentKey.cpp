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
	
}

void NewIdentKey::setupSM9UI()
{
	// 创建 SM9 相关的 UI 元素
	sm9Widget = new QWidget(this);
	QGridLayout *gridLayout2 = new QGridLayout(sm9Widget);
	gridLayout2->setContentsMargins(0, 0, 0, 0);  // 减少边距以保持与上方标签的对齐
	
	// 创建标签和输入框
	idLabel = new QLabel(tr("User ID:"), sm9Widget);
	idInput = new QLineEdit(sm9Widget);
	
	masterKeyPassLabel = new QLabel(tr("User Password:"), sm9Widget);
	masterKeyPass = new QLineEdit(sm9Widget);
	masterKeyPass->setEchoMode(QLineEdit::Password);
	
	// 添加控件到网格布局，确保标签在左边一列，输入框在右边一列
	// 这与UI文件中的布局方式一致
	gridLayout2->addWidget(idLabel, 0, 0);
	gridLayout2->addWidget(idInput, 0, 1);
	gridLayout2->addWidget(masterKeyPassLabel, 1, 0);
	gridLayout2->addWidget(masterKeyPass, 1, 1);
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
		// 根据密钥类型设置SM9类型
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
	qDebug() << "Starting SM9 key generation...";
	qDebug() << "Key Name:" << keyName;
	
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
	
	// 获取SM9类型
	int idx = keyType->currentIndex();
	QVariant q = keyType->itemData(idx);
	if (!q.isValid()) {
		errorMsg = tr("Invalid key type selected");
		return false;
	}
	
	keyListItem currentItem = q.value<keyListItem>();
	QString sm9Type = (currentItem.ktype.type == EVP_PKEY_SM9_SIGN) ? "sm9sign" : "sm9encrypt";
	
	// 创建keyjob对象
	keyjob job;
	job.ktype = currentItem.ktype;
	job.sm9Type = sm9Type;
	job.userId = userId;
	job.masterKeyPass = masterKeyPassword;
	
	// 调用db_key的newIdentKey方法生成密钥
	pki_key *key = Database.model<db_key>()->newIdentKey(job, keyName);
	if (!key) {
		errorMsg = tr("Failed to generate SM9 key");
		return false;
	}
	
	return true;
}