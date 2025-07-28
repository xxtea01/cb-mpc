# ETH客户端使用说明

## 📁 项目结构

```
demos-go/cmd/eth-client/
├── eth_client_standalone.go  # 主程序源码
├── go.mod                    # Go模块文件
├── build.sh                  # 构建脚本
├── run.sh                    # 快速启动脚本
├── README.md                 # 详细说明文档
├── USAGE.md                  # 使用说明（本文件）
└── eth-client               # 编译后的可执行文件
```

## 🚀 快速开始

### 1. 启动服务

在4个不同的终端中启动threshold-ecdsa-web服务：

```bash
# 终端 1
cd demos-go/cmd/threshold-ecdsa-web
./demo-runner -index=0

# 终端 2
cd demos-go/cmd/threshold-ecdsa-web
./demo-runner -index=1

# 终端 3
cd demos-go/cmd/threshold-ecdsa-web
./demo-runner -index=2

# 终端 4
cd demos-go/cmd/threshold-ecdsa-web
./demo-runner -index=3
```

### 2. 运行ETH客户端

```bash
cd demos-go/cmd/eth-client
./run.sh
```

## 🔧 构建和运行

### 手动构建

```bash
cd demos-go/cmd/eth-client
./build.sh
```

### 直接运行

```bash
cd demos-go/cmd/eth-client
./eth-client
```

## 📊 执行流程

1. **连接检查**: 客户端会检查所有4个服务是否可访问
2. **建立连接**: 依次连接所有参与方
3. **执行DKG**: 通过Party 0启动分布式密钥生成
4. **提取结果**: 从HTML响应中解析DKG结果
5. **生成地址**: 使用公钥坐标生成ETH地址

## 🔍 输出说明

### 成功输出示例

```
=== ETH地址生成流程 ===

🔗 连接所有参与方...
   连接 Party 0 (http://127.0.0.1:7080)...
   ✅ Party 0 连接成功
   连接 Party 1 (http://127.0.0.1:7081)...
   ✅ Party 1 连接成功
   连接 Party 2 (http://127.0.0.1:7082)...
   ✅ Party 2 连接成功
   连接 Party 3 (http://127.0.0.1:7083)...
   ✅ Party 3 连接成功
✅ 所有参与方连接成功

🚀 执行DKG协议 (阈值: 3/4)...
✅ DKG协议执行成功

📋 DKG结果:
   连接时间: 1.234s
   X-Share: base64_encoded_data
   PEM公钥: -----BEGIN PUBLIC KEY-----...

🔐 生成ETH地址...
   X坐标: 3a9bedc74e4ed202c28f8df9bd14df6f0e97c08f380b35b03724d00feceae839
   Y坐标: e00475c5827682177a3fa3eec9e95f105f26fdeb17fc66521216bf6de920a74a
   ETH地址: 0x8db675f9be0872458424351aaa7d6bdb42b6813d

🎉 ETH地址生成完成!
   地址: 0x8db675f9be0872458424351aaa7d6bdb42b6813d
   阈值: 3/4
   注意: 这是一个演示地址，实际使用时请确保安全性

✅ 流程完成!
```

## ⚠️ 故障排除

### 常见错误

1. **连接失败**
   ```
   ❌ Party 0 连接失败: Get "http://127.0.0.1:7080/api/dkg/connect": dial tcp 127.0.0.1:7080: connect: connection refused
   ```
   **解决方案**: 确保所有4个服务都已启动

2. **DKG执行失败**
   ```
   ❌ DKG执行失败: DKG执行失败，状态码: 500, 响应: ...
   ```
   **解决方案**: 检查服务日志，确保所有参与方都在线

3. **编译错误**
   ```
   ❌ 编译失败
   ```
   **解决方案**: 确保Go版本 >= 1.21，运行 `go mod tidy`

### 调试步骤

1. **检查服务状态**
   ```bash
   curl http://127.0.0.1:7080
   curl http://127.0.0.1:7081
   curl http://127.0.0.1:7082
   curl http://127.0.0.1:7083
   ```

2. **查看服务日志**
   ```bash
   # 在服务终端中查看输出
   ```

3. **检查端口占用**
   ```bash
   lsof -i :7080
   lsof -i :7081
   lsof -i :7082
   lsof -i :7083
   ```

## 🔐 安全说明

- 这是一个演示系统，生成的地址仅用于测试
- 实际使用时请确保网络安全和密钥安全
- 建议在生产环境中使用真实的TLS证书
- 定期进行密钥刷新以提高安全性

## 📞 技术支持

如果遇到问题，请检查：

1. 服务是否正常启动
2. 网络连接是否正常
3. 端口是否被占用
4. Go环境是否正确配置

详细技术文档请参考 `README.md`。 