# 网络信息安全密码算法编程

期中作业

## 环境

- Python 3.8+
- Flask
- cryptography

```bash
pip install flask cryptography
```

## 项目结构

```
├── crypto_algorithms.py   # 密码算法实现（对称/哈希/编解码/公钥）
├── api_server.py          # Flask API 接口
├── test_client.py         # API 测试脚本
├── report_generator.py    # 报告脚本
└── report.html            # 作业报告（浏览器打印为PDF）
```

## 运行

### 测试密码算法

```bash
python crypto_algorithms.py
```

### 启动 API 服务

```bash
python api_server.py
```

服务地址：`http://127.0.0.1:5000`

### 测试 API 接口

先启动服务，再执行：

```bash
python test_client.py
```

### 输出作业报告

```bash
python report_generator.py
```

浏览器打开 `report.html`，Ctrl+P 打印为 PDF。

## API 示例

```bash
# AES 加密
curl -X POST http://127.0.0.1:5000/api/aes/encrypt \
  -H "Content-Type: application/json" \
  -d '{"data": "Hello World", "mode": "CBC"}'

# SHA256 哈希
curl -X POST http://127.0.0.1:5000/api/sha256/hash \
  -H "Content-Type: application/json" \
  -d '{"data": "Hello World"}'

# Base64 编码
curl -X POST http://127.0.0.1:5000/api/base64/encode \
  -H "Content-Type: application/json" \
  -d '{"data": "Hello World"}'
```

## 程序逻辑

### crypto_algorithms.py

核心模块，包含五个类：

- `SymmetricCrypto`：对称加密。AES 基于 `cryptography` 库，支持 CBC/ECB/CFB/OFB/CTR 模式，PKCS7 填充。SM4 同样调用 `cryptography` 的 SM4 实现。RC6 按照 RFC 2040 手工实现，包括密钥扩展（P32/Q32 常量、S 盒与 L 数组混合）、128 位块加密/解密（20 轮 Feistel 网络，每轮使用数据依赖循环移位）、PKCS7 填充。
- `HashAlgorithms`：哈希与摘要。SHA1/SHA256/SHA3-256 调用 hashlib 内置函数。RIPEMD160 通过 `hashlib.new('ripemd160')` 使用 OpenSSL。HMAC 调用 `hmac` 标准库，PBKDF2 调用 `cryptography` 的 PBKDF2HMAC，迭代次数和输出长度可配置。
- `CodecAlgorithms`：Base64 和 UTF-8 编解码，直接使用 Python 标准库。
- `AsymmetricCrypto`：RSA 支持 1024 位密钥生成、OAEP-SHA1 加解密、PKCS1v15-SHA1 签名验签。ECC 使用 SECP192R1 曲线，支持 ECDH 密钥交换和 ECDSA-SHA1 签名。全部调用 `cryptography` 库。
- `CryptoAPI`：统一调度类。`execute(algorithm, action, **params)` 方法接收算法名和操作名，路由到对应类的对应方法，统一返回 `{'status', 'message', 'data'}` 字典。所有异常在内部捕获。

### api_server.py

Flask 应用，提供 RESTful 接口：

- `/`：服务信息和算法列表
- `/api/health`：健康检查，返回 `{'status': 'ok'}`
- `/api/algorithms`：返回所有算法支持的操作和参数
- `/api/<algorithm>/<action>`：通用接口，支持 POST（JSON body）和 GET（query string）两种方式，内部调用 `CryptoAPI.execute()`，返回 JSON

### test_client.py

通过 HTTP 调用 API 服务，遍历所有算法加密/解密/哈希/签名/验签操作，验证返回结果是否正确。不依赖外部测试框架，只用 `urllib.request` 发请求，`print` 输出测试状态。

### report_generator.py

调用 `CryptoAPI` 跑一遍所有算法测试，收集加密/解密/哈希/签名结果，拼成 HTML 页面输出到 `report.html`。HTML 内嵌 CSS，浏览器打开后可直接打印为 PDF。
