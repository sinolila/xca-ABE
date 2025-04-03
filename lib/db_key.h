/* vi: set sw=4 ts=4:
 *
 * Copyright (C) 2001 - 2015 Christian Hohnstaedt.
 *
 * All rights reserved.
 */

#ifndef __DB_KEY_H
#define __DB_KEY_H

#include "pki_export.h"
#include "db_base.h"
#include "pki_key.h"
#include "xfile.h"
#include <QStringList>

class QModelIndex;
class QContextMenuEvent;
class pki_x509req;
class pki_x509;
class x509rev;
class pk11_attlist;

class db_key: public db_base
{
	Q_OBJECT

	protected:
		virtual dbheaderList getHeaders();
	public:
		db_key();
		QList<pki_key*> getUnusedKeys();
		QList<pki_key*> getAllKeys();
		pki_base *newPKI(enum pki_type type = asym_key);
		void inToCont(pki_base *pki);
		void remFromCont(const QModelIndex &idx);
		pki_base* insert(pki_base *item);
		void setOwnPass(QModelIndex idx, enum pki_key::passType);
		void loadContainer();
		pki_key *newKey(const keyjob &job, const QString &name);
		pki_key *newSM9Key(const keyjob &job, const QString &name);
		int exportFlags(const QModelIndex &index) const;
		void exportItem(const QModelIndex &index,
			const pki_export *xport, XFile &file) const;
		void updateKeyEncryptionScheme();
		void resetPKI(pki_base *pki, QString name);

	signals:
		void delKey(pki_key *delkey);
		void newKey(pki_key *newkey);
		void keyDone(pki_key *nkey);
};

#endif
