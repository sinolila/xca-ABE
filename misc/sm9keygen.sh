#!/bin/bash

# 定义固定参数
MASTER_KEY_PASS="P@ssw0rd"
MASTER_SIGN_KEY_FILE="sm9sign_msk.pem"
MASTER_ENC_KEY_FILE="sm9enc_msk.pem"

# 检查参数
if [ $# -lt 3 ]; then
    echo "用法: $0 <alg> <user_id> <outpass>"
    echo "参数说明:"
    echo "  alg: sm9sign 或 sm9encrypt"
    echo "  user_id: 用户标识"
    echo "  outpass: 用户密钥的密码"
    exit 1
fi

ALG=$1
USER_ID=$2
OUTPASS=$3

# 根据算法设置主密钥文件和输出文件路径
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

# 如果主密钥不存在，则生成主密钥
if [ ! -f "$MASTER_KEY_FILE" ]; then
    echo "Master key file not found. Generating master key..."
    gmssl sm9setup -alg "$ALG" -pass "$MASTER_KEY_PASS" -out "$MASTER_KEY_FILE"
    echo "Master key generated successfully: $MASTER_KEY_FILE"
else
    echo "Master key already exists: $MASTER_KEY_FILE"
        # 命令执行失败处理
    if [ $? -ne 0 ]; then
        echo "Error: Failed to execute master key generation command."
        exit 1
    fi

    # 判断文件是否真正创建成功
    if [ ! -s "$MASTER_KEY_FILE" ]; then
        echo "Error: Master key file was not created successfully."
        exit 1
    fi
fi


# 如果用户密钥已存在则直接跳过
if [ -f "$OUT_FILE" ]; then
    echo "User key already exists: $OUT_FILE"
    exit 0
fi

# 生成用户密钥
echo "Generating user key..."
gmssl sm9keygen -alg "$ALG" \
    -in "$MASTER_KEY_FILE" \
    -inpass "$MASTER_KEY_PASS" \
    -id "$USER_ID" \
    -out "$OUT_FILE" \
    -outpass "$OUTPASS"



# 判断用户密钥是否写入成功
if [ ! -s "$OUT_FILE" ]; then
    echo "Error: User key file was not created successfully."
    exit 1
fi

echo "User key generated successfully: $OUT_FILE"