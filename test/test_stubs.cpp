#include "lib/database_model.h"
#include "lib/pki_x509.h"
#include "lib/pki_x509req.h"
#include "lib/pki_temp.h"
#include "lib/db_base.h"
#include <QModelIndex>

// db_x509 和 db_x509req 存根
class db_x509 : public db_base {
public:
    db_x509() : db_base("") {}
    void newItem() {}
    void newCert(pki_temp*) {}
    void newCert(pki_x509req*) {}
    void revoke(QList<QModelIndex>) {}
    void certRenewal(QList<QModelIndex>) {}
    void writeIndex(QString, bool) {}
};

class db_x509req : public db_base {
public:
    db_x509req() : db_base("") {}
    void newItem() {}
    void newItem(pki_temp*, pki_x509req*) {}
};

// 禁用运行时测试的更多存根
namespace CertDetail {
    void showCert(QWidget*, pki_x509super*) {}
}

namespace CrlDetail {
    void showCrl(QWidget*, pki_crl*) {}
}

class CertExtend {
public:
    CertExtend(QWidget*, pki_x509*) {}
};

class Revocation {
public:
    Revocation(QList<QModelIndex>, QWidget*) {}
    void* getRevocation() { return nullptr; }
}; 