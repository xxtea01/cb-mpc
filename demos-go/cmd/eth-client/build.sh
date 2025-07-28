#!/bin/bash

# ETH客户端构建脚本

set -e

echo "=== ETH客户端构建 ==="
echo

# 检查Go环境
if ! command -v go &> /dev/null; then
    echo "❌ 错误: 未找到Go编译器"
    exit 1
fi

echo "✅ Go环境检查通过"
echo

# 更新依赖
echo "📦 更新依赖..."
go mod tidy
echo "✅ 依赖更新完成"
echo

# 编译
echo "🔧 编译ETH客户端..."
go build -o eth-client .
if [ $? -eq 0 ]; then
    echo "✅ 编译成功"
    echo
    echo "🚀 运行客户端:"
    echo "   ./eth-client"
    echo
    echo "📋 使用说明请查看 README.md"
else
    echo "❌ 编译失败"
    exit 1
fi 