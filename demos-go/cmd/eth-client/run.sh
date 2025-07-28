#!/bin/bash

# ETH客户端快速启动脚本

set -e

echo "=== ETH地址生成客户端 ==="
echo

# 检查可执行文件是否存在
if [ ! -f "./eth-client" ]; then
    echo "🔧 编译客户端..."
    ./build.sh
fi

echo "🚀 启动ETH客户端..."
echo "请确保4个threshold-ecdsa-web服务已启动:"
echo "   Party 0: http://127.0.0.1:7080"
echo "   Party 1: http://127.0.0.1:7081"
echo "   Party 2: http://127.0.0.1:7082"
echo "   Party 3: http://127.0.0.1:7083"
echo

# 运行客户端
./eth-client 