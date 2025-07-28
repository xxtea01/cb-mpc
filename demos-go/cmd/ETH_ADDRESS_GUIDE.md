# Threshold ECDSA Web - ETH地址生成指南

## 概述

这个系统使用阈值ECDSA协议来生成分布式ETH地址。多个参与方协作生成一个ETH密钥对，任何单个参与方都无法单独控制地址。

## 🚀 快速开始

### 1. 启动系统

在4个不同的终端窗口中运行以下命令：

```bash
# 终端 1 - Party 0
./demo-runner -index=0

# 终端 2 - Party 1  
./demo-runner -index=1

# 终端 3 - Party 2
./demo-runner -index=2

# 终端 4 - Party 3
./demo-runner -index=3
```

### 2. 访问Web界面

在浏览器中打开以下地址：

- **Party 0**: http://127.0.0.1:7080/page/dkg
- **Party 1**: http://127.0.0.1:7081/page/dkg
- **Party 2**: http://127.0.0.1:7082/page/dkg
- **Party 3**: http://127.0.0.1:7083/page/dkg

## 📋 生成ETH地址的步骤

### 步骤1: 分布式密钥生成 (DKG)

1. **连接参与方**
   - 在任意一个Web界面中点击"Connect"按钮
   - 系统将建立所有参与方之间的安全连接

2. **配置阈值**
   - 设置参与方数量（默认4个）
   - 设置阈值要求（例如：3/4，需要4个参与方中的3个协作）

3. **启动DKG协议**
   - 点击"Start DKG"按钮
   - 系统将执行分布式密钥生成协议

4. **查看结果**
   - 协议完成后，每个参与方都会获得密钥份额
   - 系统会显示生成的公钥信息

### 步骤2: 生成ETH地址

从生成的公钥中，您可以：

1. **提取公钥坐标**
   - 公钥格式：`Point(x: ..., y: ...)`
   - 使用x和y坐标生成ETH地址

2. **转换为ETH地址**
   ```javascript
   // 示例JavaScript代码
   const secp256k1 = require('secp256k1');
   const keccak256 = require('keccak256');
   
   // 从公钥坐标创建完整公钥
   const publicKey = Buffer.concat([
       Buffer.from([0x04]), // 未压缩格式前缀
       Buffer.from(xCoordinate, 'hex'),
       Buffer.from(yCoordinate, 'hex')
   ]);
   
   // 计算ETH地址
   const hash = keccak256(publicKey.slice(1)); // 移除前缀
   const address = '0x' + hash.slice(-20).toString('hex');
   ```

### 步骤3: 协作签名

1. **切换到签名页面**
   - 点击导航栏中的"Threshold Signing"标签

2. **输入消息**
   - 输入要签名的消息（例如：交易哈希）

3. **选择参与方**
   - 选择参与签名的参与方（需要满足阈值要求）

4. **执行签名**
   - 点击"Sign"按钮
   - 系统将执行协作签名协议

5. **验证签名**
   - 使用生成的公钥验证签名
   - 签名符合标准ECDSA格式

## 🔧 技术细节

### 密钥格式

生成的密钥信息包括：
- **公钥**: secp256k1椭圆曲线上的点
- **密钥份额**: 每个参与方持有的私钥份额
- **阈值**: 需要协作的参与方数量

### 安全特性

- **阈值安全**: 需要足够数量的参与方协作
- **隐私保护**: 任何单个参与方都无法获得完整私钥
- **前向安全**: 支持密钥刷新，提高安全性

### ETH地址生成

ETH地址基于以下步骤：
1. 从公钥点(x, y)创建完整公钥
2. 计算公钥的Keccak256哈希
3. 取哈希的最后20字节作为地址

## 📊 示例输出

### DKG结果示例
```
✅ DKG completed successfully!

Public Key: Point(x: 3a9bedc74e4ed202c28f8df9bd14df6f0e97c08f380b35b03724d00feceae839, 
                  y: e00475c5827682177a3fa3eec9e95f105f26fdeb17fc66521216bf6de920a74a)

Key Shares:
- Party 0: x_i = Scalar(6410fce8a3c2dee44febb55faa88ab1ce28b0991e352258dad29c9d39095c438)
- Party 1: x_i = Scalar(4d834db43e1ece41b18deb10dad8cfdbd7be43bb75473506cbcc3ea1b51aebbd)
- Party 2: x_i = Scalar(...)
- Party 3: x_i = Scalar(...)
```

### 对应的ETH地址
```
0x742d35Cc6634C0532925a3b8D4C9db96C4b4d8b6
```

## 🛠️ 故障排除

### 常见问题

1. **连接失败**
   - 确保所有4个参与方都已启动
   - 检查证书是否正确生成
   - 确认端口没有被占用

2. **DKG失败**
   - 检查阈值设置是否合理
   - 确保所有参与方都在线
   - 查看日志文件获取详细错误信息

3. **签名失败**
   - 确保选择了足够的参与方（满足阈值）
   - 检查密钥份额是否正确加载
   - 验证消息格式

### 日志文件

系统会生成详细的日志文件：
- `party-0.log` - Party 0的日志
- `party-1.log` - Party 1的日志
- `party-2.log` - Party 2的日志
- `party-3.log` - Party 3的日志

## 🔐 安全建议

1. **生产环境部署**
   - 使用真实的TLS证书
   - 部署在安全的网络环境中
   - 定期轮换密钥

2. **密钥管理**
   - 安全存储密钥份额
   - 定期进行密钥刷新
   - 实施访问控制策略

3. **监控和审计**
   - 记录所有操作日志
   - 监控异常活动
   - 定期安全审计

## 📞 技术支持

如果遇到问题，请检查：
1. 系统日志文件
2. 网络连接状态
3. 证书配置
4. 阈值设置

这个系统为ETH地址生成提供了一个安全、分布式的解决方案！ 