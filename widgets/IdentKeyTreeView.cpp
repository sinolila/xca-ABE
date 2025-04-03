/* vi: set sw=4 ts=4:
 *
 * Copyright (C) 2020 Christian Hohnstaedt.
 *
 * All rights reserved.
 */

#include "lib/pki_scard.h"
#include "lib/load_obj.h"
#include "IdentKeyTreeView.h"
#include "MainWindow.h"
#include "KeyDetail.h"
#include "NewIdentKey.h"
#include "ExportDialog.h"
#include "XcaWarning.h"
#include <QAbstractItemView>
#include <QMenu>

void IdentKeyTreeView::fillContextMenu(QMenu *menu, QMenu *subExport,
			const QModelIndex &index, QModelIndexList indexes)
{
	bool multi = indexes.size() > 1;

	pki_key *key = db_base::fromIndex<pki_key>(index);
	if (indexes.size() == 0 || !key)
		return;

	if (!multi && key && key->isPrivKey() && !key->isToken()) {
		switch (key->getOwnPass()) {
		case pki_key::ptCommon:
			menu->addAction(tr("Change password"), this,
					SLOT(setOwnPass()));
			break;
		case pki_key::ptPrivate:
			menu->addAction(tr("Reset password"), this,
					SLOT(resetOwnPass()));
			break;
		default:
			break;
		}
	}

	if (!pkcs11::libraries.loaded() || multi)
		return;

	if (key->isToken()) {
		menu->addAction(tr("Change PIN"), this,
			SLOT(changePin()));
		menu->addAction(tr("Init PIN with SO PIN (PUK)"), this,
			SLOT(initPin()));
		menu->addAction(tr("Change SO PIN (PUK)"), this,
			SLOT(changeSoPin()));
	} else if (subExport) {
		subExport->addAction(tr("Security token"),
			this, SLOT(toToken()));
	}
}

void IdentKeyTreeView::setOwnPass()
{
	if (!basemodel)
		return;
	try {
		keys()->setOwnPass(currentIndex(), pki_key::ptPrivate);
	} catch (errorEx &err) {
		XCA_ERROR(err);
	}
}

void IdentKeyTreeView::resetOwnPass()
{
	if (!basemodel)
		return;
	try {
		keys()->setOwnPass(currentIndex(), pki_key::ptCommon);
	} catch (errorEx &err) {
		XCA_ERROR(err);
	}
}

void IdentKeyTreeView::changePin()
{
	pki_scard *scard;
	QModelIndex currentIdx = currentIndex();

	if (!currentIdx.isValid())
		return;
	scard = db_base::fromIndex<pki_scard>(currentIdx);
	try {
		if (!scard->isToken()) {
			throw errorEx(tr("This is not a token"));
		}
		scard->changePin();
	} catch (errorEx &err) {
		XCA_ERROR(err);
	}
}

void IdentKeyTreeView::initPin()
{
	pki_scard *scard;
	QModelIndex currentIdx = currentIndex();

	if (!currentIdx.isValid())
		return;
	scard = db_base::fromIndex<pki_scard>(currentIdx);
	try {
		if (!scard->isToken()) {
			throw errorEx(tr("This is not a token"));
		}
		scard->initPin();
	} catch (errorEx &err) {
		XCA_ERROR(err);
	}
}

void IdentKeyTreeView::changeSoPin()
{
	pki_scard *scard;
	QModelIndex currentIdx = currentIndex();

	if (!currentIdx.isValid())
		return;
	scard = db_base::fromIndex<pki_scard>(currentIdx);
	try {
		if (!scard->isToken()) {
			throw errorEx(tr("This is not a token"));
		}
		scard->changeSoPin();
	} catch (errorEx &err) {
		XCA_ERROR(err);
	}
}

void IdentKeyTreeView::toToken()
{
	QModelIndex currentIdx = currentIndex();

	if (!currentIdx.isValid() || !basemodel)
		return;

	pki_key *key = db_base::fromIndex<pki_key>(currentIdx);
	if (!key || !pkcs11::libraries.loaded() || key->isToken())
		return;

	pki_scard *card = NULL;
	try {
		pkcs11 p11;
		slotid slot;

		if (!p11.selectToken(&slot, mainwin))
			return;
		card = new pki_scard(key->getIntName());
		card->store_token(slot, key->decryptKey());
		card->pkiSource = key->pkiSource;
		QString msg = tr("Shall the original key '%1' be replaced by the key on the token?\nThis will delete the key '%1' and make it unexportable").
			arg(key->getIntName());
		if (XCA_YESNO(msg)) {
			keys()->deletePKI(currentIdx);
			keys()->insertPKI(card);
			card = NULL;
		}
	} catch (errorEx &err) {
		XCA_ERROR(err);
	}
	delete card;
}

void IdentKeyTreeView::showPki(pki_base *pki)
{
	pki_key *key = dynamic_cast<pki_key *>(pki);
	KeyDetail::showKey(this, key);
}

void IdentKeyTreeView::newItem() {
	newItem("");
}

void IdentKeyTreeView::newItem(const QString &name)
{
	if (!basemodel)
		return;

	NewIdentKey *dlg = new NewIdentKey(this, name);//初始化，栈内存动态获取

	if (dlg->exec()) {
		keyjob job = dlg->getKeyJob();
		// 处理IBC密钥
		keys()->newKey(job, dlg->keyDesc->text());//db_key为标识密钥重构一份
	}
	delete dlg;
}

void IdentKeyTreeView::load(void)
{
	load_key l;
	load_default(&l);
}

ExportDialog *IdentKeyTreeView::exportDialog(const QModelIndexList &indexes)
{
	if (indexes.size() == 0)
		return NULL;
	pki_key *key = db_base::fromIndex<pki_key>(indexes[0]);
	return new ExportDialog(this,
		tr("Key export"),
		tr("Private Keys ( *.pem *.der *.pk8 );; "
		   "SSH Public Keys ( *.pub )") + ";;" +
		tr("SSH Private Keys ( *.priv )") + ";;" +
		tr("Microsoft PVK Keys ( *.pvk )"), indexes,
		QPixmap(key->isToken() ? ":scardImg" : ":keyImg"),
		pki_export::select(asym_key, basemodel->exportFlags(indexes)),
		"keyexport");
}
