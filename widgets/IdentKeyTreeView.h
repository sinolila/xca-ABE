/* vi: set sw=4 ts=4:
 *
 * Copyright (C) 2006 - 2015 Christian Hohnstaedt.
 *
 * All rights reserved.
 */

#ifndef __IDENTKEYTREEVIEW_H
#define __IDENTKEYTREEVIEW_H

#include "XcaTreeView.h"
#include "lib/db_key.h"

class QAction;
class IdentKeyTreeView: public XcaTreeView
{
	Q_OBJECT

	db_key *keys() const
	{
		return dynamic_cast<db_key*>(basemodel);
	}

  public:
	IdentKeyTreeView(QWidget *parent) : XcaTreeView(parent)
	{
		ClipboardSettings = "KeyFormat";
		ClipboardPki_type = asym_key;
	}
	void fillContextMenu(QMenu *menu, QMenu *subExport,
			const QModelIndex &index, QModelIndexList indexes);
	void showPki(pki_base *pki);
	ExportDialog *exportDialog(const QModelIndexList &indexes);

  public slots:
	void resetOwnPass();
	void setOwnPass();
	void changePin();
	void initPin();
	void changeSoPin();
	void toToken();
	void newItem();
	void load();
	void newItem(const QString &name);
};
#endif
