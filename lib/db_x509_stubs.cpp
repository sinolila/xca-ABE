#include "db_x509.h"
#include "db_x509req.h"
#include "pki_temp.h"
#include <QModelIndex>

// db_x509 ���ʵ��
void db_x509::newItem()
{
    // ��ʵ��
}

void db_x509::newCert(pki_temp* temp)
{
    (void)temp; // ��ֹδʹ�þ���
    // ��ʵ��
}

void db_x509::newCert(pki_x509req* req)
{
    (void)req; // ��ֹδʹ�þ���
    // ��ʵ��
}

void db_x509::certRenewal(QList<QModelIndex> indexes)
{
    (void)indexes; // ��ֹδʹ�þ���
    // ��ʵ��
}

void db_x509::revoke(QList<QModelIndex> indexes)
{
    (void)indexes; // ��ֹδʹ�þ���
    // ��ʵ��
}

// db_x509req ���ʵ��
void db_x509req::newItem()
{
    // ��ʵ��
}

void db_x509req::newItem(pki_temp* temp, pki_x509req* req)
{
    (void)temp; // ��ֹδʹ�þ���
    (void)req;  // ��ֹδʹ�þ���
    // ��ʵ��
} 