# CB-MPC Go 项目构建指南

## 概述

CB-MPC 项目包含 C++ 核心库和 Go 语言绑定。要成功编译 Go 部分，需要先编译 C++ 库，然后编译 Go 绑定。

## 系统要求

- macOS (已在 macOS 14.5.0 上测试)
- Go 1.23.0 或更高版本
- C++ 编译器 (Clang/AppleClang)
- OpenSSL 3.x (通过 Homebrew 安装)
- CMake 3.x

## 快速构建

运行构建脚本：
```bash
./build-go.sh
```

## 手动构建步骤

### 1. 安装依赖

确保已安装 OpenSSL：
```bash
brew install openssl@3
```

### 2. 编译 C++ 核心库

```bash
# 编译 C++ 库
make build

# 安装到系统路径 (需要 sudo 权限)
sudo make install
```

### 3. 编译 Go 绑定

```bash
cd demos-go/cb-mpc-go

# 更新依赖
go mod tidy

# 编译 Go 代码
CGO_ENABLED=1 go build ./...
```

### 4. 运行测试

```bash
# 运行 Go 测试
CGO_ENABLED=1 go test ./...
```

### 5. 运行示例

```bash
# 返回项目根目录
cd ../..

# 运行所有示例
bash ./scripts/run-demos.sh --run-all

# 或运行特定示例
bash ./scripts/run-demos.sh --run access-structure
bash ./scripts/run-demos.sh --run agreerandom
bash ./scripts/run-demos.sh --run ecdsa-2pc
bash ./scripts/run-demos.sh --run ecdsa-mpc-with-backup
bash ./scripts/run-demos.sh --run zk
```

## 项目结构

```
demos-go/
├── cb-mpc-go/          # Go 绑定库 (github.com/xxtea01/cb-mpc/demos-go/cb-mpc-go)
│   ├── api/            # 公共 API
│   ├── internal/       # 内部实现
│   └── go.mod          # Go 模块文件
├── examples/           # 示例程序
│   ├── access-structure/ (github.com/xxtea01/cb-mpc/demo-go-access-structure)
│   ├── agreerandom/    (github.com/xxtea01/cb-mpc/demo-go-agreerandom)
│   ├── ecdsa-2pc/      (github.com/xxtea01/cb-mpc/demo-go-ecdsa-2pc)
│   ├── ecdsa-mpc-with-backup/ (github.com/xxtea01/cb-mpc/demo-go-ecdsa-mpc-with-backup)
│   └── zk/             (github.com/xxtea01/cb-mpc/demo-go-zk)
└── cmd/               # 命令行工具
    └── threshold-ecdsa-web/ (github.com/xxtea01/cb-mpc/demo-runner)
```

## 故障排除

### OpenSSL 头文件找不到

如果遇到 `'openssl/aes.h' file not found` 错误：

1. 确保 OpenSSL 已正确安装：
   ```bash
   brew install openssl@3
   ```

2. 检查 OpenSSL 路径：
   ```bash
   brew --prefix openssl@3
   ```

3. 确保 CGO 环境变量正确设置：
   ```bash
   export CGO_CFLAGS="-I/opt/homebrew/opt/openssl/include"
   export CGO_LDFLAGS="-L/opt/homebrew/opt/openssl/lib"
   ```

### 库链接错误

如果遇到库链接错误，确保 C++ 库已正确安装：

```bash
# 检查库文件是否存在
ls -la /usr/local/opt/cbmpc/lib/libcbmpc.a

# 重新安装库
sudo make install
```

## 验证构建

运行以下命令验证构建是否成功：

```bash
# 编译测试
cd demos-go/cb-mpc-go
CGO_ENABLED=1 go build ./...

# 运行测试
CGO_ENABLED=1 go test ./...

# 运行示例
cd ../..
bash ./scripts/run-demos.sh --run-all
```

所有示例都应该成功运行并显示预期的输出。 