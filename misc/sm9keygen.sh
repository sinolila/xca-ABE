#!/bin/bash

# SM9 密钥生成脚本
# 用法1: sm9keygen.sh -setup -type [sign|encrypt] -pass password -out master.pem [-pubout pubkey.pem]
# 用法2: sm9keygen.sh -type [sign|encrypt] -master master.pem -pass password -id user_id -out output.pem [-outpass password]

TYPE=""
MASTER_KEY=""
MASTER_PASS=""
USER_ID=""
OUTPUT_FILE=""
OUTPUT_PASS=""
PUBOUT_FILE=""
SETUP_MODE=false

# 解析参数
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
            echo "未知选项: $1"
            exit 1
            ;;
    esac
done

# 检查 GmSSL 是否安装
if ! command -v gmssl &> /dev/null; then
    echo "GmSSL 工具未找到，请确保已安装 GmSSL 并添加到 PATH 中"
    exit 1
fi

# 根据模式执行不同的操作
if [ "$SETUP_MODE" = true ]; then
    # 主密钥生成模式
    if [ -z "$TYPE" ] || [ -z "$MASTER_PASS" ] || [ -z "$OUTPUT_FILE" ]; then
        echo "缺少必要参数"
        echo "用法: sm9keygen.sh -setup -type [sign|encrypt] -pass password -out master.pem [-pubout pubkey.pem]"
        exit 1
    fi
    
    # 将类型参数转换为 GmSSL 使用的格式
    if [ "$TYPE" = "sign" ]; then
        SM9_ALG="sm9sign"
    elif [ "$TYPE" = "encrypt" ]; then
        SM9_ALG="sm9encrypt"
    else
        echo "无效的类型: $TYPE，必须是 sign 或 encrypt"
        exit 1
    fi
    
    # 调用 GmSSL 工具生成主密钥
    echo "执行命令: gmssl sm9setup -alg $SM9_ALG -pass [PASSWORD] -out $OUTPUT_FILE"
    
    if [ -z "$PUBOUT_FILE" ]; then
        gmssl sm9setup -alg $SM9_ALG -pass "$MASTER_PASS" -out "$OUTPUT_FILE"
    else
        gmssl sm9setup -alg $SM9_ALG -pass "$MASTER_PASS" -out "$OUTPUT_FILE" -pubout "$PUBOUT_FILE"
    fi
    
    # 检查执行结果
    if [ $? -eq 0 ]; then
        echo "SM9 主密钥生成成功: $OUTPUT_FILE"
        exit 0
    else
        echo "SM9 主密钥生成失败"
        exit 1
    fi
    
else
    # 用户密钥生成模式
    if [ -z "$TYPE" ] || [ -z "$MASTER_KEY" ] || [ -z "$MASTER_PASS" ] || [ -z "$USER_ID" ] || [ -z "$OUTPUT_FILE" ]; then
        echo "缺少必要参数"
        echo "用法: sm9keygen.sh -type [sign|encrypt] -master master.pem -pass password -id user_id -out output.pem [-outpass password]"
        exit 1
    fi
    
    # 将类型参数转换为 GmSSL 使用的格式
    if [ "$TYPE" = "sign" ]; then
        SM9_ALG="sm9sign"
    elif [ "$TYPE" = "encrypt" ]; then
        SM9_ALG="sm9encrypt"
    else
        echo "无效的类型: $TYPE，必须是 sign 或 encrypt"
        exit 1
    fi
    
    # 如果没有指定输出密码，使用主密钥密码
    if [ -z "$OUTPUT_PASS" ]; then
        OUTPUT_PASS="$MASTER_PASS"
    fi
    
    # 调用 GmSSL 工具生成用户密钥
    echo "执行命令: gmssl sm9keygen -alg $SM9_ALG -in $MASTER_KEY -inpass [PASSWORD] -id $USER_ID -out $OUTPUT_FILE -outpass [PASSWORD]"
    
    gmssl sm9keygen -alg $SM9_ALG -in "$MASTER_KEY" -inpass "$MASTER_PASS" -id "$USER_ID" -out "$OUTPUT_FILE" -outpass "$OUTPUT_PASS"
    
    # 检查执行结果
    if [ $? -eq 0 ]; then
        echo "SM9 用户密钥生成成功: $OUTPUT_FILE"
        echo "$OUTPUT_PASS" > "${OUTPUT_FILE}.pass"
        exit 0
    else
        echo "SM9 用户密钥生成失败"
        exit 1
    fi
fi 