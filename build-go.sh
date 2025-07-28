#!/bin/bash

set -e

echo "=== CB-MPC Go 构建脚本 ==="

# 检查是否在正确的目录
if [ ! -f "CMakeLists.txt" ]; then
    echo "错误: 请在项目根目录运行此脚本"
    exit 1
fi

echo "1. 编译 C++ 核心库..."
make build

echo "2. 安装 C++ 库到系统路径..."
sudo make install

echo "3. 编译 Go 绑定..."
cd demos-go/cb-mpc-go
CGO_ENABLED=1 go build ./...

echo "4. 运行 Go 测试..."
CGO_ENABLED=1 go test ./...

echo "5. 测试示例程序..."
cd ../..
bash ./scripts/run-demos.sh --run access-structure
bash ./scripts/run-demos.sh --run agreerandom
bash ./scripts/run-demos.sh --run ecdsa-2pc

echo "=== 构建完成！ ==="
echo "Go 项目已成功编译并测试通过。"
echo "所有示例程序都能正常运行。" 