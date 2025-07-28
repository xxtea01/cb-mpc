# ETH地址生成客户端

这是一个Go客户端程序，用于调用4个threshold-ecdsa-web服务来生成ETH地址。

## 功能特性

- 🔗 自动连接4个参与方服务
- 🚀 执行分布式密钥生成(DKG)协议
- 🔐 从公钥生成ETH地址
- 📊 显示详细的执行结果

## 使用方法

### 1. 启动服务

首先需要启动4个threshold-ecdsa-web服务：

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

### 2. 编译客户端

```bash
cd demos-go/cmd/eth-client
go build -o eth-client .
```

### 3. 运行客户端

```bash
./eth-client
```

## 服务地址

客户端会连接到以下服务：

- Party 0: http://127.0.0.1:7080
- Party 1: http://127.0.0.1:7081
- Party 2: http://127.0.0.1:7082
- Party 3: http://127.0.0.1:7083

## 执行流程

1. **连接参与方**: 客户端会依次连接所有4个参与方
2. **执行DKG**: 通过Party 0启动分布式密钥生成协议
3. **提取公钥**: 从DKG结果中提取公钥信息
4. **生成地址**: 使用公钥坐标生成ETH地址

## 输出示例

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

## 技术细节

### 阈值设置

默认阈值为3/4，意味着需要4个参与方中的3个协作才能生成签名。

### ETH地址生成

1. 从DKG结果中提取公钥坐标(x, y)
2. 创建完整的公钥格式：0x04 + x + y
3. 计算Keccak256哈希（移除0x04前缀）
4. 取哈希的最后20字节作为ETH地址

### 安全特性

- 分布式密钥生成，任何单个参与方都无法获得完整私钥
- 阈值签名，需要足够数量的参与方协作
- 支持密钥刷新，提高安全性

## 故障排除

### 常见问题

1. **连接失败**
   - 确保所有4个服务都已启动
   - 检查端口是否被占用
   - 确认防火墙设置

2. **DKG失败**
   - 检查阈值设置是否合理
   - 确保所有参与方都在线
   - 查看服务日志

3. **编译错误**
   - 确保Go版本 >= 1.21
   - 运行 `go mod tidy` 更新依赖

## 开发说明

这个客户端使用HTTP API与threshold-ecdsa-web服务通信，主要调用以下端点：

- `GET /api/dkg/connect` - 连接参与方
- `GET /api/dkg/execute?threshold=N` - 执行DKG协议

客户端会解析HTML响应来提取DKG结果，然后使用公钥坐标生成ETH地址。 