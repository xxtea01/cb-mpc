# MPC项目Docker构建指南

## 概述

这个Docker配置可以在Linux环境下完整构建和运行MPC项目，包括C++核心库、Go应用和ETH客户端。

## 🐳 Docker环境特性

- ✅ **多阶段构建**: 分别构建C++和Go组件
- ✅ **完整环境**: 包含所有必要的依赖和工具
- ✅ **服务编排**: 使用Docker Compose运行多个服务
- ✅ **端口映射**: 支持Web界面访问
- ✅ **数据持久化**: 配置文件挂载

## 🚀 快速开始

### 方法1: 使用Docker Compose (推荐)

```bash
# 构建并启动所有服务
docker-compose up --build

# 后台运行
docker-compose up -d --build

# 查看日志
docker-compose logs -f

# 停止服务
docker-compose down
```

### 方法2: 手动构建和运行

```bash
# 构建镜像
./docker-build.sh

# 运行单个容器
docker run -it --rm mpc-project:latest

# 运行Web服务 (带端口映射)
docker run -it --rm -p 7080:7080 -p 7081:7081 -p 7082:7082 -p 7083:7083 mpc-project:latest
```

## 📁 项目结构

```
.
├── Dockerfile              # 多阶段构建配置
├── docker-compose.yml      # 服务编排配置
├── docker-build.sh         # 构建脚本
├── DOCKER_README.md        # 本文件
└── demos-go/
    └── cmd/
        ├── threshold-ecdsa-web/  # Web服务
        └── eth-client/           # ETH客户端
```

## 🔧 构建过程

### 阶段1: C++核心库构建
- 使用Ubuntu 22.04作为基础镜像
- 安装构建工具和依赖
- 编译C++核心库
- 安装到系统路径

### 阶段2: Go应用构建
- 使用Go 1.21镜像
- 复制C++库文件
- 构建Go应用和ETH客户端
- 设置CGO环境

### 阶段3: 运行环境
- 使用轻量级Ubuntu镜像
- 复制编译好的应用
- 配置运行时环境
- 暴露必要端口

## 🌐 服务访问

构建完成后，可以通过以下地址访问服务：

- **Party 0**: http://localhost:7080
- **Party 1**: http://localhost:7081
- **Party 2**: http://localhost:7082
- **Party 3**: http://localhost:7083

## 📊 容器内命令

进入容器后可以运行以下命令：

```bash
# 启动Web服务
./demo-runner -index=0  # Party 0
./demo-runner -index=1  # Party 1
./demo-runner -index=2  # Party 2
./demo-runner -index=3  # Party 3

# 运行ETH客户端
./eth-client

# 查看帮助
./demo-runner --help
./eth-client --help
```

## 🔍 调试和故障排除

### 查看容器状态
```bash
# 查看运行中的容器
docker ps

# 查看所有容器
docker ps -a

# 查看容器日志
docker logs mpc-party-0
docker logs mpc-party-1
docker logs mpc-party-2
docker logs mpc-party-3
docker logs mpc-eth-client
```

### 进入容器调试
```bash
# 进入特定容器
docker exec -it mpc-party-0 /bin/bash
docker exec -it mpc-eth-client /bin/bash

# 查看容器内文件
docker exec -it mpc-party-0 ls -la /app
```

### 常见问题

1. **构建失败**
   ```bash
   # 清理Docker缓存
   docker system prune -a
   
   # 重新构建
   docker-compose build --no-cache
   ```

2. **端口冲突**
   ```bash
   # 修改docker-compose.yml中的端口映射
   ports:
     - "8080:7080"  # 改为其他端口
   ```

3. **权限问题**
   ```bash
   # 确保脚本有执行权限
   chmod +x docker-build.sh
   ```

## 🔐 安全说明

- 容器内运行的应用仅用于开发和测试
- 生产环境部署需要额外的安全配置
- 建议使用Docker secrets管理敏感信息
- 定期更新基础镜像以修复安全漏洞

## 📈 性能优化

### 构建优化
```bash
# 使用多阶段构建减少镜像大小
# 使用.dockerignore排除不必要文件
# 并行构建多个服务
```

### 运行时优化
```bash
# 设置资源限制
docker run --memory=2g --cpus=2 mpc-project:latest

# 使用数据卷持久化数据
docker run -v mpc-data:/app/data mpc-project:latest
```

## 🛠️ 开发模式

### 本地开发
```bash
# 挂载源代码目录
docker run -v $(pwd):/workspace mpc-project:latest

# 实时重新构建
docker-compose up --build
```

### 调试模式
```bash
# 启用调试日志
docker run -e DEBUG=1 mpc-project:latest

# 使用开发镜像
docker build --target go-builder -t mpc-dev .
```

## 📞 技术支持

如果遇到问题：

1. 检查Docker和Docker Compose版本
2. 查看构建日志和运行日志
3. 确认系统资源是否充足
4. 验证网络连接和端口配置

详细技术文档请参考项目根目录的README文件。 

export https_proxy=http://127.0.0.1:7890 http_proxy=http://127.0.0.1:7890 all_proxy=socks5://127.0.0.1:7890