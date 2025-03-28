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
#include "lib/pkcs11.h"
#include "distname.h"
#include "clicklabel.h"
#include "ItemCombo.h"
#include <QLabel>
#include <QPushButton>
#include <QLineEdit>
#include <QStringList>

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
#ifndef OPENSSL_NO_EC
		if (m == CKM_EC_KEY_PAIR_GEN) {
			CK_MECHANISM_INFO info;
			p11->mechanismInfo(slot, m, &info);
			ec_flags = info.flags & (CKF_EC_F_P | CKF_EC_F_2M);
			if (!ec_flags) {
				/* Fallback: Assume to support both for
				 * libraries leaving this flag empty
				 */
				ec_flags = CKF_EC_F_P | CKF_EC_F_2M;
			}
		}
#endif
		printname = QString("%1 #%2 (%3 Key of %4 - %5 bits)").
			arg(ti.label()).arg(ti.serial()).
			arg(ktype.name).
			arg(minKeySize).
			arg(maxKeySize);
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
	static const QList<int> sizeList = { 1024, 2048, 4096, 8192 };
	slotidList p11_slots;
	QList<keyListItem> keytypes;

	setupUi(this);
	setWindowTitle(XCA_TITLE);
	image->setPixmap(QPixmap(":keyImg"));
	mainwin->helpdlg->register_ctxhelp_button(this, "keygen");

	if (!name.isEmpty())
		keyDesc->setText(name);

	// ����Ϊ���ɼ�����ΪIBC����Ҫ��Щ�ؼ�
	keyLength->setVisible(false);
	keySizeLabel->setVisible(false);
	
	// ��������ѡ�����ΪIBC��Ҫѡ������
	curveBox->setVisible(true);
	curveLabel->setVisible(true);
	curveLabel->setText(tr("Curve name"));

	// ֻ���IBC������ߣ�������ͨ��EC����
	populateIBCParameters();
	
	// ֻ���IBC����
	foreach (const keytype t, keytype::types()) {
		if (t.type == EVP_PKEY_IBC) {
			keytypes << keyListItem(t);
		}
	}

	keyDesc->setFocus();
	
	if (pkcs11::libraries.loaded()) try {
		pkcs11 p11;
		p11_slots = p11.getSlotList();

		foreach(slotid slot, p11_slots) {
			QList<CK_MECHANISM_TYPE> ml = p11.mechanismList(slot);
			// ֻ���IBC��ص�Token����
			foreach(keytype t, keytype::types()) {
				if (t.type == EVP_PKEY_IBC && ml.contains(t.mech))
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
		if (!keytypes[i].card &&
		    keytypes[i].type() == EVP_PKEY_IBC)
		{
			keyType->setCurrentIndex(i);
		}
	}
	
	// ���û��IBCѡ����һ��Ĭ�ϵ�
	if (keyType->count() == 0) {
		foreach (const keytype t, keytype::types()) {
			if (t.type == EVP_PKEY_IBC) {
				QVariant q;
				keyListItem item(t);
				q.setValue(item);
				keyType->addItem(item.printname, q);
				break;
			}
		}
	}
	
	buttonBox->button(QDialogButtonBox::Ok)->setText(tr("Create"));
}

// ����·�����ר���������IBC���������updateCurves��
void NewIdentKey::populateIBCParameters()
{
	curveBox->clear();
	
	// ���IBC���õĲ���/����
	// �������Ԥ����ģ�����������EC���߿�
	curveBox->addItem("SM9", 0);  // ʹ���Զ���ID���ʵ���NID
	curveBox->addItem("IBE-Boneh-Franklin", 1);
	// ������Ӹ���IBC����
	
	curveBox->setCurrentIndex(0);  // Ĭ��ѡ���һ��
}

void NewIdentKey::on_keyType_currentIndexChanged(int idx)
{
	keyListItem ki = keyType->itemData(idx).value<keyListItem>();
	rememberDefault->setEnabled(!ki.card);
	
	// IBC����ʼ����ʾ����ѡ��򣬵�������Կ����ѡ���
	curveBox->setVisible(true);
	curveLabel->setVisible(true);
	keySizeLabel->setVisible(false);
	keyLength->setVisible(false);
}

keyjob NewIdentKey::getKeyJob() const
{
	keyjob job;
	keyListItem selected = keyType->itemData(keyType->currentIndex())
						.value<keyListItem>();
	job.ktype = selected.ktype;
	
	// ����IBC�������������ʹ��ec_nid���洢IBC����ID��
	job.ec_nid = curveBox->currentData().toInt();
	
	job.slot = selected.slot;
	return job;
}

void NewIdentKey::accept()
{
	if (rememberDefault->isChecked()) {
		keyjob::defaultjob = getKeyJob();
		Settings["defaultkey"] = keyjob::defaultjob.toString();
	}
	QDialog::accept();
}
