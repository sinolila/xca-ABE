#!/bin/bash

# SM9 ��Կ���ɽű�
# �÷�1: sm9keygen.sh -setup -type [sign|encrypt] -pass password -out master.pem [-pubout pubkey.pem]
# �÷�2: sm9keygen.sh -type [sign|encrypt] -master master.pem -pass password -id user_id -out output.pem [-outpass password]

TYPE=""
MASTER_KEY=""
MASTER_PASS=""
USER_ID=""
OUTPUT_FILE=""
OUTPUT_PASS=""
PUBOUT_FILE=""
SETUP_MODE=false

# ��������
while [[ $# -gt 0 ]]; do
    key="$1"
    case $key in
        -setup)
            SETUP_MODE=true
            shift
            ;;
        -type)
            TYPE="$2"
            shift 2
            ;;
        -master)
            MASTER_KEY="$2"
            shift 2
            ;;
        -pass)
            MASTER_PASS="$2"
            shift 2
            ;;
        -id)
            USER_ID="$2"
            shift 2
            ;;
        -out)
            OUTPUT_FILE="$2"
            shift 2
            ;;
        -outpass)
            OUTPUT_PASS="$2"
            shift 2
            ;;
        -pubout)
            PUBOUT_FILE="$2"
            shift 2
            ;;
        *)
            echo "δ֪ѡ��: $1"
            exit 1
            ;;
    esac
done

# ��� GmSSL �Ƿ�װ
if ! command -v gmssl &> /dev/null; then
    echo "GmSSL ����δ�ҵ�����ȷ���Ѱ�װ GmSSL ����ӵ� PATH ��"
    exit 1
fi

# ����ģʽִ�в�ͬ�Ĳ���
if [ "$SETUP_MODE" = true ]; then
    # ����Կ����ģʽ
    if [ -z "$TYPE" ] || [ -z "$MASTER_PASS" ] || [ -z "$OUTPUT_FILE" ]; then
        echo "ȱ�ٱ�Ҫ����"
        echo "�÷�: sm9keygen.sh -setup -type [sign|encrypt] -pass password -out master.pem [-pubout pubkey.pem]"
        exit 1
    fi
    
    # �����Ͳ���ת��Ϊ GmSSL ʹ�õĸ�ʽ
    if [ "$TYPE" = "sign" ]; then
        SM9_ALG="sm9sign"
    elif [ "$TYPE" = "encrypt" ]; then
        SM9_ALG="sm9encrypt"
    else
        echo "��Ч������: $TYPE�������� sign �� encrypt"
        exit 1
    fi
    
    # ���� GmSSL ������������Կ
    echo "ִ������: gmssl sm9setup -alg $SM9_ALG -pass [PASSWORD] -out $OUTPUT_FILE"
    
    if [ -z "$PUBOUT_FILE" ]; then
        gmssl sm9setup -alg $SM9_ALG -pass "$MASTER_PASS" -out "$OUTPUT_FILE"
    else
        gmssl sm9setup -alg $SM9_ALG -pass "$MASTER_PASS" -out "$OUTPUT_FILE" -pubout "$PUBOUT_FILE"
    fi
    
    # ���ִ�н��
    if [ $? -eq 0 ]; then
        echo "SM9 ����Կ���ɳɹ�: $OUTPUT_FILE"
        exit 0
    else
        echo "SM9 ����Կ����ʧ��"
        exit 1
    fi
    
else
    # �û���Կ����ģʽ
    if [ -z "$TYPE" ] || [ -z "$MASTER_KEY" ] || [ -z "$MASTER_PASS" ] || [ -z "$USER_ID" ] || [ -z "$OUTPUT_FILE" ]; then
        echo "ȱ�ٱ�Ҫ����"
        echo "�÷�: sm9keygen.sh -type [sign|encrypt] -master master.pem -pass password -id user_id -out output.pem [-outpass password]"
        exit 1
    fi
    
    # �����Ͳ���ת��Ϊ GmSSL ʹ�õĸ�ʽ
    if [ "$TYPE" = "sign" ]; then
        SM9_ALG="sm9sign"
    elif [ "$TYPE" = "encrypt" ]; then
        SM9_ALG="sm9encrypt"
    else
        echo "��Ч������: $TYPE�������� sign �� encrypt"
        exit 1
    fi
    
    # ���û��ָ��������룬ʹ������Կ����
    if [ -z "$OUTPUT_PASS" ]; then
        OUTPUT_PASS="$MASTER_PASS"
    fi
    
    # ���� GmSSL ���������û���Կ
    echo "ִ������: gmssl sm9keygen -alg $SM9_ALG -in $MASTER_KEY -inpass [PASSWORD] -id $USER_ID -out $OUTPUT_FILE -outpass [PASSWORD]"
    
    gmssl sm9keygen -alg $SM9_ALG -in "$MASTER_KEY" -inpass "$MASTER_PASS" -id "$USER_ID" -out "$OUTPUT_FILE" -outpass "$OUTPUT_PASS"
    
    # ���ִ�н��
    if [ $? -eq 0 ]; then
        echo "SM9 �û���Կ���ɳɹ�: $OUTPUT_FILE"
        echo "$OUTPUT_PASS" > "${OUTPUT_FILE}.pass"
        exit 0
    else
        echo "SM9 �û���Կ����ʧ��"
        exit 1
    fi
fi 