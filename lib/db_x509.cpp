/* vi: set sw=4 ts=4:
 *
 * Copyright (C) 2001 - 2014 Christian Hohnstaedt.
 *
 * All rights reserved.
 */

#include "db_x509.h"
#include "db_x509req.h"
#include "db_crl.h"
#include "pki_x509.h"
#include "pki_crl.h"
#include "pki_temp.h"
#include "pki_pkcs12.h"
#include "pki_pkcs7.h"
#include "pki_evp.h"
#include "pki_scard.h"
#include "pass_info.h"
#include "database_model.h"
#include "entropy.h"

#include "XcaWarningCore.h"
#include "PwDialogCore.h"

#pragma message ("drop UI dependencies")
#include "ui_NewX509.h"
#include "widgets/CertExtend.h"
#include "widgets/RevocationList.h"
#include "widgets/NewX509.h"
#include "widgets/MainWindow.h"

#include "ui_RevocationList.h"
#include "ui_MainWindow.h"
#include "ui_CertExtend.h"
#include "ui_Revoke.h"
#include "ui_Help.h"

#include <openssl/rand.h>

db_x509::db_x509() : db_x509super("certificates")
{
	sqlHashTable = "certs";
	pkitype << x509;
	pkitype_depends << x509_req;
	updateHeaders();
	loadContainer();
}

void db_x509::loadContainer()
{
	db_x509super::loadContainer();

	XSqlQuery q("SELECT item, issuer FROM certs WHERE issuer is NOT NULL");
	while (q.next()) {
		pki_base *root = treeItem;
		pki_x509 *cert = Store.lookupPki<pki_x509>(q.value(0));
		pki_x509 *issuer = Store.lookupPki<pki_x509>(q.value(1));
		if (cert && issuer) {
			cert->setSigner(issuer);
			if (cert != issuer)
				root = issuer;
		}
		if (cert && cert->getParent() != root) {
			qDebug() << "MOVE" << cert->getIntName()
				<< "from" << cert->getParent()->getIntName()
				<< "to" << root->getIntName();
			treeItem->takeChild(cert);
			root->insert(cert);
		}
	}
	emit columnsContentChanged();
}

dbheaderList db_x509::getHeaders()
{
	dbheaderList h = db_x509super::getHeaders();
	h <<	new dbheader(HD_cert_ca, true, tr("CA"),
			tr("reflects the basic Constraints extension")) <<
		new num_dbheader(HD_cert_serial, true, tr("Serial")) <<
		new num_dbheader(HD_cert_md5fp, false,tr("MD5 fingerprint")) <<
		new num_dbheader(HD_cert_sha1fp,false,tr("SHA1 fingerprint")) <<
		new num_dbheader(HD_cert_sha256fp,false,tr("SHA256 fingerprint")) <<
		new date_dbheader(HD_cert_notBefore, false,tr("Start date"),
				tr("Not before")) <<
		new date_dbheader(HD_cert_notAfter, true, tr("Expiry date"),
				tr("Not after")) <<
		new date_dbheader(HD_cert_revocation,false, tr("Revocation")) <<
		new date_dbheader(HD_cert_crl_expire,true, tr("CRL Expiration"));
	return h;
}

pki_base *db_x509::newPKI(enum pki_type type)
{
	(void)type;
	return new pki_x509();
}

QList<pki_x509 *> db_x509::getAllIssuers()
{
	/* Select X509 CA certificates with available private key */
	return Store.sqlSELECTpki<pki_x509>(
		"SELECT x509super.item FROM x509super "
		"JOIN private_keys ON x509super.pkey = private_keys.item "
		"JOIN certs ON certs.item = x509super.item "
		"WHERE certs.ca=1") +
		Store.sqlSELECTpki<pki_x509>(
		"SELECT x509super.item FROM x509super "
		"JOIN tokens ON x509super.pkey = tokens.item "
		"JOIN certs ON certs.item = x509super.item "
		"WHERE certs.ca=1");
}

void db_x509::remFromCont(const QModelIndex &idx)
{
	if (!idx.isValid())
		return;
	db_crl *crls = Database.model<db_crl>();
	db_x509super::remFromCont(idx);
	pki_base *pki = fromIndex(idx);
	pki_x509 *child;
	pki_base *new_parent;
	QList<pki_x509 *> childs;

	Transaction;
	if (!TransBegin())
		return;

	while (pki->childCount()) {
		child = dynamic_cast<pki_x509*>(pki->takeFirst());
		child->delSigner(dynamic_cast<pki_x509*>(pki));
		new_parent = child->findIssuer();
		insertChild(child, new_parent);
		if (new_parent)
			childs << child;
	}
	XSqlQuery q;
	SQL_PREPARE(q, "UPDATE certs SET issuer=? WHERE item=?");
	foreach(pki_x509 *child, childs) {
		q.bindValue(0, child->getSigner()->getSqlItemId());
		q.bindValue(1, child->getSqlItemId());
		AffectedItems(child->getSqlItemId());
		q.exec();
	}
	crls->removeSigner(pki);
	TransCommit();
}

static bool recursiveSigning(pki_x509 *cert, pki_x509 *client)
{
	/* recursive signing check */
	for (pki_x509 *s = cert->getSigner(); s; s = s->getSigner()) {
		if (s == s->getSigner()) {
			return false;
		}
		if (s == client) {
			qWarning() << "Recursive signing:" << s->getIntName()
				<< "<->" << cert->getIntName();
			return true;
		}
	}
	return false;
}

void db_x509::inToCont(pki_base *pki)
{
	pki_x509 *cert = dynamic_cast<pki_x509*>(pki);
	cert->setParent(nullptr);
	pki_base *root = cert->getSigner();

	insertChild(cert, root);

	QList<pki_x509 *> childs;
	QList<pki_x509 *> items;
	unsigned pubhash = cert->pubHash();
	unsigned namehash = cert->getSubject().hashNum();
	x509revList revList;

	/* Search for another certificate (name and key)
	 * and use its childs if we are newer */
	items = Store.sqlSELECTpki<pki_x509>(
		"SELECT x509super.item FROM x509super "
		"JOIN certs ON certs.item = x509super.item "
		"WHERE certs.ca=1 AND x509super.subj_hash=? "
		"AND x509super.key_hash=?",
			QList<QVariant>() << namehash << pubhash);
	foreach(pki_x509 *other, items) {
		if (other == cert)
			continue;
		if (!other->compareNameAndKey(cert))
			continue;
		if (cert->getNotAfter() < other->getNotAfter())
			continue;
		foreach(pki_base *b, other->getChildItems()) {
			pki_x509 *child = dynamic_cast<pki_x509*>(b);
			if (!child)
				continue;
			child->delSigner(other);
			childs << child;
		}
		revList.merge(other->getRevList());
	}
	/* Search rootItem childs, whether they are ours */
	foreach(pki_base *b, treeItem->getChildItems()) {
		pki_x509 *child = dynamic_cast<pki_x509*>(b);
		if (!child || child == cert || child->getSigner() == child)
			continue;
		if (child->verify_only(cert))
			childs << child;
	}
	/* move collected childs to us */
	XSqlQuery q;
	x509revList revokedChilds;
	SQL_PREPARE(q, "UPDATE certs SET issuer=? WHERE item=?");
	q.bindValue(0, cert->getSqlItemId());
	foreach(pki_x509 *child, childs) {
		if (recursiveSigning(cert, child))
			continue;
		if (!child->verify(cert))
			continue;
		insertChild(child, cert);
		q.bindValue(1, child->getSqlItemId());
		AffectedItems(child->getSqlItemId());
		q.exec();
		XCA_SQLERROR(q.lastError());
		if (child->isRevoked())
			revokedChilds << child->getRevocation();
	}
	q.finish();
	revList.merge(revokedChilds);
	cert->setRevocations(revList);

	/* Update CRLs */
	QList<pki_crl *> crls = Store.sqlSELECTpki<pki_crl>(
			"SELECT item FROM crls WHERE iss_hash=?",
			QList<QVariant>() << namehash);
	SQL_PREPARE(q, "UPDATE crls SET issuer=? WHERE item=?");
	foreach(pki_crl *crl, crls) {
		crl->verify(cert);
		if (cert != crl->getIssuer())
			continue;
		q.bindValue(0, cert->getSqlItemId());
		q.bindValue(1, crl->getSqlItemId());
		AffectedItems(crl->getSqlItemId());
		q.exec();
		XCA_SQLERROR(q.lastError());
	}
}

QList<pki_x509*> db_x509::getCerts(bool unrevoked)
{
	QList<pki_x509*> c;
	c.clear();
	foreach(pki_x509 *pki, Store.getAll<pki_x509>()) {
		if (unrevoked && pki->isRevoked())
			continue;
		c.append(pki);
	}
	return c;
}

void db_x509::writeIndex(const QString &fname, bool hierarchy) const
{
	if (hierarchy) {
		QString dir = fname + "/";
		if (!QDir().mkpath(fname)) {
			throw errorEx(tr("Failed to create directory '%1'")
				.arg(fname));
		}
		QList<pki_x509*> issuers = Store.sqlSELECTpki<pki_x509>(
			"SELECT DISTINCT issuer FROM certs WHERE issuer != item");
		foreach(pki_x509 *ca, issuers) {
			XFile file(dir + ca->getUnderlinedName() + ".txt");
			file.open_write();
			writeIndex(file, Store.sqlSELECTpki<pki_x509>(
				"SELECT item FROM certs WHERE issuer=?",
				QList<QVariant>()<<QVariant(ca->getSqlItemId()))
			);
		}
	} else {
		XFile file(fname);
		file.open_write();
		writeIndex(file, Store.sqlSELECTpki<pki_x509>(
					"SELECT item FROM certs"));
	}
}

static a1int randomSerial()
{
	unsigned char buf[SHA512_DIGEST_LENGTH];
	unsigned char md[SHA512_DIGEST_LENGTH];

	Entropy::seed_rng();

	RAND_bytes(buf, SHA512_DIGEST_LENGTH);
	SHA512(buf, SHA512_DIGEST_LENGTH, md);
	a1int serial;
	if (md[0] && md[0] < 0x80)
		serial.setRaw(md, (int)Settings["serial_len"] / 8);
	return serial;
}

a1int db_x509::getUniqueSerial(pki_x509 *signer)
{
	// returns an unused unique serial
	a1int serial, signer_serial;
	x509rev rev;
	x509revList revList;
	if (signer) {
		signer_serial = signer->getSerial();
		revList = signer->getRevList();
	}
	for (int i=0; ; i++) {
		if (i > 100)
			throw errorEx(tr("Failed to retrieve unique random serial"));
		serial = randomSerial();
		if (serial == a1int(0L))
			continue;
		if (!signer)
			break;
		if (signer_serial == serial)
			continue;
		rev.setSerial(serial);
		if (revList.contains(rev))
			continue;
		if (signer->getBySerial(serial))
			continue;
		break;
	}
	return serial;
}

pki_base *db_x509::insert(pki_base *item)
{
	pki_x509 *cert = dynamic_cast<pki_x509 *>(item);
	pki_x509 *oldcert = dynamic_cast<pki_x509 *>(getByReference(cert));
	if (oldcert) {
		XCA_INFO(tr("The certificate already exists in the database as:\n'%1'\nand so it was not imported").arg(oldcert->getIntName()));
		delete cert;
		return NULL;
	}
	return insertPKI(cert);
}

void db_x509::markRequestSigned(pki_x509req *req, pki_x509 *cert)
{
	if (!req || !cert)
		return;
	pki_x509 *issuer = cert->getSigner();

	Transaction;
	if (!TransBegin())
		return;

	XSqlQuery q;
	req->setDone();
	SQL_PREPARE(q, "UPDATE requests SET signed=? WHERE item=?");
	q.bindValue(0, 1);
	q.bindValue(1, req->getSqlItemId());
	AffectedItems(req->getSqlItemId());
	q.exec();

	a1time a;
	req->selfComment(tr("Signed on %1 by '%2'").arg(a.toPretty())
		.arg(issuer ? issuer->getIntName() : tr("Unknown")));
	SQL_PREPARE(q, "UPDATE items SET comment=? WHERE id=?");
	q.bindValue(0, req->getComment());
	q.bindValue(1, req->getSqlItemId());
	q.exec();

	TransCommit();
}

int db_x509::exportFlags(const QModelIndex &idx) const
{
	QStringList filt;
	int disable_flags = 0;

	pki_x509 *crt = fromIndex<pki_x509>(idx);
	if (!crt)
		return 0;

	pki_key *privkey = crt->getRefKey();

	if (!crt->getSigner() || crt->getSigner() == crt)
		disable_flags |= F_CHAIN;

	if (!privkey || !privkey->isPrivKey() || privkey->isToken())
		disable_flags |= F_PRIVATE;

	if (!crt->isCA())
		disable_flags |= F_CA;

	pki_key *key = crt->getPubKey();
	if (key && key->getKeyType() != EVP_PKEY_RSA && key->getJWKcrv().isEmpty())
		disable_flags |= F_JWK;
	delete key;

	return disable_flags;
}

void db_x509::writeTaggedPEM(const BioByteArray &b, const QString &tag, XFile &file)
{
	if (b.size() > 0) {
		file.write(QString("<%1>\n").arg(tag).toLatin1());
		file.write(b.byteArray());
		file.write(QString("</%1>\n").arg(tag).toLatin1());
	}
}

void db_x509::exportItems(const QModelIndexList &list,
			const pki_export *xport, XFile &file) const
{
	if (list.empty())
		return;

	pki_x509 *oldcrt = nullptr, *crt = fromIndex<pki_x509>(list[0]);

	QList<pki_x509*> certs;
	foreach(QModelIndex idx, list) {
		pki_x509 *x = fromIndex<pki_x509>(idx);
		if (x)
			certs << x;
	}

	if (xport->match_all(F_PEM)) {
		if (xport->match_all(F_CHAIN)) {
			for (; crt && crt != oldcrt; oldcrt = crt, crt = crt->getSigner())
				crt->writeCert(file, true);
		} else if (xport->match_all(F_UNREVOKED)) {
			foreach(pki_x509 *pki, Store.getAll<pki_x509>())
				if (!pki->isRevoked())
					pki->writeCert(file, true);
		} else if (xport->match_all(F_UNUSABLE)) {
			foreach(pki_x509 *pki, Store.getAll<pki_x509>())
				if (pki->unusable())
					pki->writeCert(file, true);
		} else if (xport->match_all(F_ALL)) {
			foreach(pki_x509 *pki, Store.getAll<pki_x509>())
				pki->writeCert(file, true);
		} else {
			if (xport->match_all(F_PRIVATE)) {
				pki_evp *pkey = (pki_evp *)crt->getRefKey();
				if (!pkey || pkey->isPubKey())
					throw errorEx(tr("There was no key found for the Certificate: '%1'").
							arg(crt->getIntName()));
				if (pkey->isToken())
					throw errorEx(tr("Not possible for a token key: '%1'").
							arg(crt->getIntName()));
				if (xport->match_all(F_PKCS8)) {
					pkey->writePKCS8(file, EVP_aes_256_cbc(),
						PwDialogCore::pwCallback, true);
				} else {
					pkey->writeKey(file, NULL, NULL, true);
				}
			}
			foreach(crt, certs)
				crt->writeCert(file, true);
		}
	} else if (xport->match_all(F_OVPN)) {
		BioByteArray key, cert, extra, ca;
		pki_evp *pkey = (pki_evp *)crt->getRefKey();
		if (pkey)
			pkey->pem(key, pki_export::by_id(20)); // PEM unencrypted
		for (; crt && crt != oldcrt; oldcrt = crt, crt = crt->getSigner())
		{
			if (crt == crt->getSigner())
				crt->pem(ca);
			else if (cert.size() == 0)
				crt->pem(cert);
			else
				crt->pem(extra);
		}
		writeTaggedPEM(ca, "ca", file);
		writeTaggedPEM(extra, "extra-certs", file);
		writeTaggedPEM(cert, "cert", file);
		writeTaggedPEM(key, "key", file);
		writeTaggedPEM(crt->getTaKey().toLatin1(), "tls-auth", file);
	} else if (xport->match_all(F_PKCS7)) {
		writePKCS7(crt, file, xport->flags, list);
	} else if (xport->match_all(F_INDEX)) {
		writeIndex(file, certs);
	} else if (xport->match_all(F_CAL)) {
		QStringList vcal;
		foreach(crt, certs) {
			vcal += xport->match_all(F_CA) ?
				crt->icsVEVENT_ca() : crt->icsVEVENT();
		}
		writeVcalendar(file, vcal);
	} else if (xport->match_all(F_TAKEY)) {
		file.write(crt->getTaKey().toLatin1());
	} else {
		qDebug() << "exportItems: db_base";
		db_base::exportItems(list, xport, file);
	}
}

void db_x509::exportItem(const QModelIndex &index,
			const pki_export *xport, XFile &file) const
{
	pki_x509 *crt = fromIndex<pki_x509>(index);

	if (xport->match_all(F_DER)) {
		crt->writeCert(file, false);
	} else if (xport->match_all(F_PKCS12)) {
		writePKCS12(crt, file, xport->match_all(F_CHAIN));
	} else if (xport->match_all(F_CONFIG)) {
		crt->opensslConf(file);
	} else {
		db_base::exportItem(index, xport, file);
	}
}

void db_x509::writeIndex(XFile &file, QList<pki_x509*> items) const
{
	QString index;
	foreach(pki_x509 *cert, items) {
		if (cert)
			index += cert->getIndexEntry();
	}
	file.write(index.toUtf8());
}

void db_x509::writePKCS12(pki_x509 *cert, XFile &file, bool chain) const
{
	QStringList filt;
	pki_pkcs12 *p12 = NULL;
	try {
		pki_evp *privkey = (pki_evp *)cert->getRefKey();
		if (!privkey || privkey->isPubKey()) {
			XCA_WARN(tr("There was no key found for the Certificate: '%1'").arg(cert->getIntName()));
			return;
		}
		if (privkey->isToken()) {
			XCA_WARN(tr("Not possible for the token-key Certificate '%1'").arg(cert->getIntName()));
			return;
		}
		p12 = new pki_pkcs12(cert->getIntName(), cert, privkey);
		pki_x509 *signer = cert->getSigner();
		while ((signer != NULL ) && (signer != cert) && chain) {
			p12->append_item(signer);
			cert = signer;
			signer = signer->getSigner();
		}
		encAlgo encAlgo((QString) Settings["pkcs12_enc_algo"]);
		p12->writePKCS12(file, encAlgo);
	}
	catch (errorEx &err) {
		XCA_ERROR(err);
	}
	delete p12;
}

void db_x509::writePKCS7(pki_x509 *cert, XFile &file, int flags,
			const QModelIndexList &list) const
{
	pki_pkcs7 *p7 = new pki_pkcs7(QString());

	try {
		if (flags & F_CHAIN) {
			while (cert) {
				p7->append_item(cert);
				if (cert->getSigner() == cert)
					break;
				cert = cert->getSigner();
			}
		} else if (flags & (F_UNREVOKED | F_ALL)) {
			foreach(pki_x509 *cer, Store.getAll<pki_x509>()) {
				if ((flags & F_ALL) || !cer->isRevoked())
					p7->append_item(cer);
			}
		} else if (flags & F_UNUSABLE) {
			foreach(pki_x509 *cer, Store.getAll<pki_x509>()) {
				if (cer->unusable())
					p7->append_item(cer);
			}
		} else if (flags) {
			foreach(QModelIndex idx, list) {
				cert = fromIndex<pki_x509>(idx);
				if (cert)
					p7->append_item(cert);
			}
		} else {
			p7->append_item(cert);
		}
		p7->writeP7(file, false);
	}
	catch (errorEx &err) {
		XCA_ERROR(err);
	}
	delete p7;
}

