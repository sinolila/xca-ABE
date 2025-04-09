#!/bin/bash

# ����̶�����
MASTER_KEY_PASS="P@ssw0rd"
MASTER_SIGN_KEY_FILE="sm9sign_msk.pem"
MASTER_ENC_KEY_FILE="sm9enc_msk.pem"

# ������
if [ $# -lt 3 ]; then
    echo "�÷�: $0 <alg> <user_id> <outpass>"
    echo "����˵��:"
    echo "  alg: sm9sign �� sm9encrypt"
    echo "  user_id: �û���ʶ"
    echo "  outpass: �û���Կ������"
    exit 1
fi

ALG=$1
USER_ID=$2
OUTPASS=$3

# �����㷨��������Կ�ļ�������ļ�·��
if [ "$ALG" = "sm9sign" ]; then
    MASTER_KEY_FILE="$MASTER_SIGN_KEY_FILE"
    OUT_FILE="sm9sign_${USER_ID}.pem"
elif [ "$ALG" = "sm9encrypt" ]; then
    MASTER_KEY_FILE="$MASTER_ENC_KEY_FILE"
    OUT_FILE="sm9enc_${USER_ID}.pem"
else
    echo "Error: algorithm must be sm9sign or sm9encrypt"
    exit 1
fi

# �������Կ�����ڣ�����������Կ
if [ ! -f "$MASTER_KEY_FILE" ]; then
    echo "Master key file not found. Generating master key..."
    gmssl sm9setup -alg "$ALG" -pass "$MASTER_KEY_PASS" -out "$MASTER_KEY_FILE"
    echo "Master key generated successfully: $MASTER_KEY_FILE"
else
    echo "Master key already exists: $MASTER_KEY_FILE"
        # ����ִ��ʧ�ܴ���
    if [ $? -ne 0 ]; then
        echo "Error: Failed to execute master key generation command."
        exit 1
    fi

    # �ж��ļ��Ƿ����������ɹ�
    if [ ! -s "$MASTER_KEY_FILE" ]; then
        echo "Error: Master key file was not created successfully."
        exit 1
    fi
fi


# ����û���Կ�Ѵ�����ֱ������
if [ -f "$OUT_FILE" ]; then
    echo "User key already exists: $OUT_FILE"
    exit 0
fi

# �����û���Կ
echo "Generating user key..."
gmssl sm9keygen -alg "$ALG" \
    -in "$MASTER_KEY_FILE" \
    -inpass "$MASTER_KEY_PASS" \
    -id "$USER_ID" \
    -out "$OUT_FILE" \
    -outpass "$OUTPASS"



# �ж��û���Կ�Ƿ�д��ɹ�
if [ ! -s "$OUT_FILE" ]; then
    echo "Error: User key file was not created successfully."
    exit 1
fi

echo "User key generated successfully: $OUT_FILE"