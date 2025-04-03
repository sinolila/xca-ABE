#ifndef __PKI_KEY_SM9_H
#define __PKI_KEY_SM9_H


class pki_key_sm9sign : public pki_key
{
public:
    pki_key_sm9sign(const QString &name);
    virtual ~pki_key_sm9sign();
    
    virtual void fromPEMFile(const QString &filename, const char *password);
    virtual void writeDefault(const QString &dirname) const;
    virtual bool isPrivKey() const;
    virtual bool isPubKey() const;
    virtual QString getTypeString() const;
    
private:
    SM9_SIGN_KEY key;
};

class pki_key_sm9encrypt : public pki_key
{
public:
    pki_key_sm9encrypt(const QString &name);
    virtual ~pki_key_sm9encrypt();
    
    virtual void fromPEMFile(const QString &filename, const char *password);
    virtual void writeDefault(const QString &dirname) const;
    virtual bool isPrivKey() const;
    virtual bool isPubKey() const;
    virtual QString getTypeString() const;
    
private:
    SM9_ENC_KEY key;
};

#endif // 