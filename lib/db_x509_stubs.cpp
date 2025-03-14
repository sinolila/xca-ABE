#include "db_x509.h"
#include "db_x509req.h"
#include "pki_temp.h"
#include <QModelIndex>

// db_x509 存根实现
void db_x509::newItem()
{
    // 空实现
}

void db_x509::newCert(pki_temp* temp)
{
    (void)temp; // 防止未使用警告
    // 空实现
}

void db_x509::newCert(pki_x509req* req)
{
    (void)req; // 防止未使用警告
    // 空实现
}

void db_x509::certRenewal(QList<QModelIndex> indexes)
{
    (void)indexes; // 防止未使用警告
    // 空实现
}

void db_x509::revoke(QList<QModelIndex> indexes)
{
    (void)indexes; // 防止未使用警告
    // 空实现
}

// db_x509req 存根实现
void db_x509req::newItem()
{
    // 空实现
}

void db_x509req::newItem(pki_temp* temp, pki_x509req* req)
{
    (void)temp; // 防止未使用警告
    (void)req;  // 防止未使用警告
    // 空实现
} 