/* vi: set sw=4 ts=4:
 *
 * Copyright (C) 2024 Christian Hohnstaedt.
 *
 * All rights reserved.
 */

#include <QTest>
#include <QThread>
#include <QDialog>
#include <QCheckBox>
#include <QDebug>

#include "widgets/MainWindow.h"
#include "ui_MainWindow.h"
#include "widgets/ImportMulti.h"
#include "ui_ImportMulti.h"
#include "widgets/CertExtend.h"
#include "ui_CertExtend.h"
#include "widgets/RevocationList.h"
#include "ui_RevocationList.h"
#include "ui_Revoke.h"

#include "lib/pki_multi.h"

#include "main.h"
#include "renewal.h"
#include "lib/load_obj.h"
#include "lib/pki_scard.h"
#include "widgets/XcaApplication.h"

#define ZERO_SECS "yyyyMMddHHmm'00Z'"
a1time not_after = a1time::now(3*356*24*60*60);

void revoke_and_renew()
{
	CertExtend *dlg = test_main::findWindow<CertExtend>("CertExtend");
	if (!dlg)
		return;
	dlg->replace->setCheckState(Qt::Checked);
	dlg->revoke->setCheckState(Qt::Checked);
	dlg->notAfter->setDate(not_after);
	dlg->buttonBox->button(QDialogButtonBox::Ok)->click();
	Revocation *rev = test_main::findWindow<Revocation>("Revoke");
	rev->buttonBox->button(QDialogButtonBox::Ok)->click();
}

void renew()
{
	CertExtend *dlg = test_main::findWindow<CertExtend>("CertExtend");
	if (!dlg)
		return;
	dlg->validNumber->setText("1");
	dlg->validRange->setCurrentIndex(1);
	dlg->applyTime->click();
	not_after = dlg->notAfter->getDate();
	dlg->replace->setCheckState(Qt::Unchecked);
	dlg->revoke->setCheckState(Qt::Unchecked);
	dlg->buttonBox->button(QDialogButtonBox::Ok)->click();
}

void renew_del_keep_serial()
{
	CertExtend *dlg = test_main::findWindow<CertExtend>("CertExtend");
	if (!dlg)
		return;
	dlg->replace->setCheckState(Qt::Checked);
	dlg->revoke->setCheckState(Qt::Unchecked);
	dlg->noWellDefinedExpDate->setCheckState(Qt::Checked);
	dlg->keepSerial->setCheckState(Qt::Checked);
	dlg->buttonBox->button(QDialogButtonBox::Ok)->click();
}

QList<pki_x509*> getcerts(const QString &name)
{
	QList<pki_x509*> l;
	foreach(pki_x509 *pki, Store.getAll<pki_x509>()) {
        if (pki->getIntName() == name)
			l << pki;
	}
	return l;
}

void test_main::validity()
{
	a1time n, time = a1time::now(), r;
	QRegExp rx("(\\d+)(\\w+)");
	int num;
	n = n.fromPlain("7y9M2d8h");
	COMPARE(n.toPlain(), QString("7y9m2d8h"));
	COMPARE(n.toString(), QString("7 years 9 months 2 days 8 hours"));
	COMPARE(n.toFancy(), QString("7 years 9 months 2 days 8 hours"));

	n.setUndefined();
	VERIFY(n.isUndefined());
	COMPARE(n.toPlain(), QString());

	n = n.now();
	n = n.addDays(365);
	time = time.addDays(365);
	n = n.addSecs(-1);
	time = time.addSecs(-1);
	VERIFY(n.get_epoch() - time.get_epoch() < 2);

	time.setUndefined();
	VERIFY(time.isUndefined());
	time = a1time(1000000000);
	COMPARE(time.toPlain(), QString("2001-09-09 03:46:40"));

	time += 1;
	COMPARE(time.toPlain(), QString("2001-09-09 03:46:41"));
	time += a1time("2d");
	COMPARE(time.toPlain(), QString("2001-09-11 03:46:41"));
	time -= a1time("2d");
	COMPARE(time.toPlain(), QString("2001-09-09 03:46:41"));

	VERIFY(time == time);
	VERIFY(time <= time);
	VERIFY(time >= time);
	VERIFY(time + 1 > time);
	VERIFY(time < time +1);
	VERIFY(time != time + 1);
	VERIFY(!(time +1 <= time));
	VERIFY(!(time >= time +1));

	time = time.fromPlain("2001-09-09 03:46:38");
	VERIFY(time.isValid());
	COMPARE(time.toPlain(), QString("2001-09-09 03:46:38"));
	r = a1time::now(a1time::SECONDS);
	r = r.fromPlain("123d10h");
	VERIFY(r.isValid());
	num = rx.indexIn(r.toPlain());
	VERIFY(num == 0);
	COMPARE(rx.cap(1), QString("123"));
	COMPARE(rx.cap(2), QString("d"));
	num = rx.indexIn(r.toPlain(), num + rx.cap(0).length());
	VERIFY(num > 0);
	COMPARE(rx.cap(1), QString("10"));
	COMPARE(rx.cap(2), QString("h"));
}

void test_main::revoke()
{
	qDebug() << "证书吊销测试已禁用";
}
