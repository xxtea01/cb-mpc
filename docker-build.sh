#!/bin/bash

# MPC项目Docker构建脚本
# 在Linux环境下构建整个MPC项目

set -e

echo "=== MPC项目Docker构建 ==="
echo

# 检查Docker是否安装
if ! command -v docker &> /dev/null; then
    echo "❌ 错误: 未找到Docker"
    echo "请先安装Docker: https://docs.docker.com/get-docker/"
    exit 1
fi

echo "✅ Docker环境检查通过"
echo

# 检查是否在项目根目录
if [ ! -f "CMakeLists.txt" ]; then
    echo "❌ 错误: 请在项目根目录运行此脚本"
    exit 1
fi

echo "📦 开始构建MPC项目Docker镜像..."
echo "   这可能需要几分钟时间，请耐心等待..."
echo

# 构建Docker镜像
docker build -t mpc-project:latest .
if [ $? -eq 0 ]; then
    echo
    echo "✅ Docker镜像构建成功!"
    echo
    echo "🚀 运行容器:"
    echo "   docker run -it --rm mpc-project:latest"
    echo
    echo "🔍 查看镜像:"
    echo "   docker images mpc-project"
    echo
    echo "📋 进入容器并运行服务:"
    echo "   docker run -it --rm mpc-project:latest /bin/bash"
    echo
    echo "🌐 运行Web服务 (需要端口映射):"
    echo "   docker run -it --rm -p 7080:7080 -p 7081:7081 -p 7082:7082 -p 7083:7083 mpc-project:latest"
    echo
    echo "📖 容器内可用的命令:"
    echo "   ./demo-runner -index=0  # 启动Party 0"
    echo "   ./demo-runner -index=1  # 启动Party 1"
    echo "   ./demo-runner -index=2  # 启动Party 2"
    echo "   ./demo-runner -index=3  # 启动Party 3"
    echo "   ./eth-client            # 运行ETH客户端"
else
    echo "❌ Docker镜像构建失败"
    exit 1
fi 