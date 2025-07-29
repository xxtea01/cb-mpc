#!/bin/bash

# Docker测试脚本
# 快速测试MPC项目的Docker构建

set -e

echo "=== MPC项目Docker测试 ==="
echo

# 检查Docker是否安装
if ! command -v docker &> /dev/null; then
    echo "❌ 错误: 未找到Docker"
    exit 1
fi

echo "✅ Docker环境检查通过"
echo

# 检查Docker Compose
if ! command -v docker-compose &> /dev/null; then
    echo "⚠️  警告: 未找到docker-compose，将使用docker命令"
    USE_COMPOSE=false
else
    echo "✅ Docker Compose环境检查通过"
    USE_COMPOSE=true
fi

echo

# 选择测试模式
echo "请选择测试模式:"
echo "1. 构建镜像并进入容器"
echo "2. 使用Docker Compose启动所有服务"
echo "3. 仅构建镜像"
echo

read -p "请输入选择 (1-3): " choice

case $choice in
    1)
        echo "🔧 构建镜像..."
        docker build -t mpc-project:test .
        
        echo "🚀 启动容器..."
        docker run -it --rm mpc-project:test /bin/bash
        ;;
    2)
        if [ "$USE_COMPOSE" = true ]; then
            echo "🔧 使用Docker Compose构建并启动服务..."
            docker-compose up --build
        else
            echo "❌ 需要Docker Compose，请先安装"
            exit 1
        fi
        ;;
    3)
        echo "🔧 仅构建镜像..."
        docker build -t mpc-project:test .
        echo "✅ 镜像构建完成"
        echo "运行: docker run -it --rm mpc-project:test"
        ;;
    *)
        echo "❌ 无效选择"
        exit 1
        ;;
esac 