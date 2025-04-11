/* vi: set sw=4 ts=4:
 *
 * Copyright (C) 2001 - 2015 Christian Hohnstaedt.
 *
 * All rights reserved.
 */

#ifndef __DB_SM9_H
#define __DB_SM9_H

#include "pki_export.h"
#include "db_base.h"
#include "pki_key.h"
#include "xfile.h"
#include <QStringList>

class pki_key;
class pki_x509super;
class pk11_attlist;
class QModelIndex;
class QContextMenuEvent;

class db_sm9: public db_base
{
    Q_OBJECT

    protected:
        virtual dbheaderList getHeaders();
    public:
        db_sm9();
        QList<pki_key*> getSM9Keys();
        pki_base *newPKI(enum pki_type type = asym_key);
        void inToCont(pki_base *pki);
        void remFromCont(const QModelIndex &idx);
        pki_base* insert(pki_base *item);
        void loadContainer();
        pki_key *newSM9Key(const keyjob &job, const QString &name);
        int exportFlags(const QModelIndex &index) const;
        void exportItem(const QModelIndex &index, 
            const pki_export *xport, XFile &file) const;
        void resetPKI(pki_base *pki, QString name);
        void setOwnPass(const QModelIndex &index, pki_key::passType type);

    signals:
        void delKey(pki_key *delkey);
        void newKey(pki_key *newkey);
        void keyDone(pki_key *nkey);
};

#endif
