# 网络信息安全密码算法编程

> **课程**：信息安全编程技术与实例开发  
> **类型**：期中作业  
> **语言**：Python 3.8+  
> **依赖**：Flask、cryptography、hashlib、hmac、pytest

---

## 1. 项目概述

本项目实现了一个完整的密码算法工具库，覆盖四大类别共 **20+ 种密码操作**，并提供 Flask RESTful API 供外部调用。

| 类别 | 算法 | 操作 |
|------|------|------|
| 对称加密 | AES、SM4、RC6 | 加密 / 解密 |
| 哈希摘要 | SHA1、SHA256、SHA3-256、RIPEMD160、HMAC-SHA1、HMAC-SHA256、PBKDF2 | 哈希 / HMAC / 密钥派生与验证 |
| 编解码 | Base64、UTF-8 | 编码 / 解码 |
| 公钥密码 | RSA、ECC、ECDSA | 密钥生成 / 加密解密 / 签名验签 / ECDH 密钥交换 |

### 关键特性

- **RC6 手工实现**：按照 RFC 2040 规范，从密钥扩展、Feistel 网络到数据依赖循环移位完全手写，不依赖第三方库
- **AES 支持 5 种工作模式**：CBC、ECB、CFB、OFB、CTR，基于 `cryptography` 库
- **统一调度接口**：`CryptoAPI.execute(algorithm, action, **params)` 一个入口调用所有算法
- **RESTful API**：Flask 应用，支持 POST 和 GET 两种请求方式
- **完整测试**：pytest 单元测试 + 独立 HTTP 客户端测试脚本
- **自动报告生成**：运行测试后生成 HTML 报告，可打印为 PDF

---

## 2. 项目结构

```
├── crypto_algorithms.py     # 核心模块：所有密码算法实现 + CryptoAPI 统一调度
├── api_server.py            # Flask Web 服务：RESTful API 接口
├── test_client.py           # API 测试客户端：通过 HTTP 请求验证 API 正确性
├── tests/
│   ├── __init__.py
│   └── test_crypto.py       # pytest 单元测试：直接测试核心模块各算法
├── report_generator.py      # 报告生成器：运行测试 → 生成 report.html
├── report.html              # 已生成的 HTML 报告（浏览器可打印为 PDF）
├── 报告.pdf                  # 期中作业报告 PDF
├── 网络信息安全密码算法编程-期中作业-要求及评分细则.pdf
├── .gitignore
└── README.md
```

### 核心模块关系

```
crypto_algorithms.py
    ├── SymmetricCrypto      # AES / SM4 / RC6
    ├── HashAlgorithms        # SHA1 / SHA256 / SHA3-256 / RIPEMD160 / HMAC / PBKDF2
    ├── CodecAlgorithms       # Base64 / UTF-8
    ├── AsymmetricCrypto      # RSA / ECC / ECDSA
    └── CryptoAPI             # 统一调度层，路由到以上四个类

api_server.py  ──调用──> CryptoAPI
test_client.py ──HTTP──> api_server.py ──调用──> CryptoAPI
tests/test_crypto.py ──直接调用──> crypto_algorithms.py
report_generator.py ──调用──> CryptoAPI ──生成──> report.html
```

---

## 3. 环境搭建与复现

### 3.1 前提条件

- Python 3.8 或更高版本
- pip 包管理器

### 3.2 安装依赖

```bash
pip install flask cryptography pytest
```

### 3.3 克隆仓库

```bash
git clone https://github.com/ganyudog/crypto-algorithms-toolkit.git
cd crypto-algorithms-toolkit
```

### 3.4 验证安装

```bash
# 直接运行核心模块，执行所有算法自测
python crypto_algorithms.py
```

预期输出包含四大类算法的测试结果，所有加密/解密往返验证、签名验签、ECDH 密钥交换均显示 `[OK]`。

---

## 4. 使用方式

### 4.1 直接调用核心模块

```python
from crypto_algorithms import CryptoAPI

api = CryptoAPI()

# AES 加密
r = api.execute('aes', 'encrypt', data='Hello World', mode='CBC')
print(r['data']['ciphertext'])
print(r['data']['key'])

# AES 解密
r2 = api.execute('aes', 'decrypt', data=r['data']['ciphertext'],
                  key=r['data']['key'], iv=r['data']['iv'], mode='CBC')
print(r2['data']['plaintext'])  # Hello World

# SHA256 哈希
r = api.execute('sha256', 'hash', data='Hello World')
print(r['data']['hash'])

# RSA 密钥生成 + 加密 + 解密
keys = api.execute('rsa', 'generate', key_size=2048)['data']
enc = api.execute('rsa', 'encrypt', data='secret',
                   public_key=keys['public_key'])
dec = api.execute('rsa', 'decrypt', data=enc['data']['ciphertext'],
                   private_key=keys['private_key'])
print(dec['data']['plaintext'])  # secret
```

### 4.2 启动 API 服务

```bash
python api_server.py
```

服务地址：`http://127.0.0.1:5000`

#### API 端点

| 端点 | 方法 | 说明 |
|------|------|------|
| `/` | GET | 服务信息和算法列表 |
| `/api/health` | GET | 健康检查 `{"status": "ok"}` |
| `/api/algorithms` | GET | 所有算法支持的操作和参数 |
| `/api/<algorithm>/<action>` | POST / GET | 通用密码算法接口 |

#### curl 示例

```bash
# AES CBC 加密
curl -X POST http://127.0.0.1:5000/api/aes/encrypt \
  -H "Content-Type: application/json" \
  -d '{"data": "Hello World", "mode": "CBC"}'

# SM4 ECB 加密
curl -X POST http://127.0.0.1:5000/api/sm4/encrypt \
  -H "Content-Type: application/json" \
  -d '{"data": "Hello World"}'

# RC6 加密（指定轮数）
curl -X POST http://127.0.0.1:5000/api/rc6/encrypt \
  -H "Content-Type: application/json" \
  -d '{"data": "Hello World", "rounds": 20, "mode": "CBC"}'

# SHA256 哈希
curl -X POST http://127.0.0.1:5000/api/sha256/hash \
  -H "Content-Type: application/json" \
  -d '{"data": "Hello World"}'

# HMAC-SHA256
curl -X POST http://127.0.0.1:5000/api/hmac-sha256/hmac \
  -H "Content-Type: application/json" \
  -d '{"key": "my_secret_key", "data": "Hello World"}'

# PBKDF2 密钥派生
curl -X POST http://127.0.0.1:5000/api/pbkdf2/derive \
  -H "Content-Type: application/json" \
  -d '{"password": "user_password", "iterations": 100000, "key_len": 32}'

# Base64 编码
curl -X POST http://127.0.0.1:5000/api/base64/encode \
  -H "Content-Type: application/json" \
  -d '{"data": "Hello World"}'

# RSA 密钥生成
curl -X POST http://127.0.0.1:5000/api/rsa/generate \
  -H "Content-Type: application/json" \
  -d '{"key_size": 2048}'

# ECC 密钥生成
curl -X POST http://127.0.0.1:5000/api/ecc/generate \
  -H "Content-Type: application/json" \
  -d '{"curve": "SECP256R1"}'
```

#### GET 方式调用

```bash
curl "http://127.0.0.1:5000/api/sha256/hash?data=Hello%20World"
curl "http://127.0.0.1:5000/api/base64/encode?data=Hello"
```

---

## 5. 算法实现细节

### 5.1 对称加密

#### AES（Advanced Encryption Standard）

- **密钥长度**：128 / 192 / 256 位（自动 SHA256 填充非标准长度密钥）
- **工作模式**：CBC、ECB、CFB、OFB、CTR
- **填充方案**：PKCS7（128 位块）
- **实现方式**：基于 `cryptography.hazmat.primitives.ciphers`

#### SM4（国密分组密码算法）

- **密钥长度**：128 位固定
- **分组长度**：128 位
- **工作模式**：ECB、CBC
- **实现方式**：基于 `cryptography` 内置 SM4 实现

#### RC6（Rivest Cipher 6）

- **参数**：w=32, r=20, b 可变（按 RFC 2040）
- **分组长度**：128 位（4 × 32 位字）
- **工作模式**：ECB、CBC（自建模式支持）
- **实现方式**：完全手工实现，包括：
  - **密钥扩展**：P32/Q32 魔数常量、S 盒初始化、L 数组混合，v=3×max(c,t) 轮迭代
  - **加密**：使用 `f(x)=x×(2x+1)` 非线性函数，数据依赖循环移位 `<<< lg w=5`
  - **解密**：逆序 Feistel 网络，逆循环移位
  - **填充**：自定义 PKCS7 风格填充（16 字节块）

### 5.2 哈希与摘要

| 算法 | 输出长度 | 实现方式 |
|------|----------|----------|
| SHA1 | 160 bits | `hashlib.sha1` |
| SHA256 | 256 bits | `hashlib.sha256` |
| SHA3-256 | 256 bits | `hashlib.sha3_256` |
| RIPEMD160 | 160 bits | `hashlib.new('ripemd160')` (OpenSSL) |
| HMAC-SHA1 | 160 bits | `hmac` 标准库 |
| HMAC-SHA256 | 256 bits | `hmac` 标准库 |
| PBKDF2 | 可配置 | `cryptography.hazmat.primitives.kdf.pbkdf2.PBKDF2HMAC` |

PBKDF2 支持：
- 可配置迭代次数（默认 100,000）
- 可配置输出密钥长度
- 3 种底层哈希：SHA1 / SHA256 / SHA512
- 派生 + 验证双重接口

### 5.3 编解码

| 算法 | 操作 | 实现 |
|------|------|------|
| Base64 | 编码 / 解码 | Python `base64` 标准库 |
| UTF-8 | 编码（→hex）/ 解码（hex→） | Python 内建 `str.encode` / `bytes.decode` |

### 5.4 公钥密码

#### RSA

- **密钥长度**：默认 2048 位，可配置
- **加密方案**：OAEP 填充，MGF1 掩码生成，SHA1 哈希
- **签名方案**：PKCS1v15 填充，支持 SHA1/SHA256
- **实现**：基于 `cryptography` 的 RSA 实现

#### ECC / ECDSA

- **支持曲线**：SECP192R1、SECP256R1、SECP384R1
- **ECDH**：基于椭圆曲线的 Diffie-Hellman 密钥交换，双方各自使用对方公钥与己方私钥计算共享密钥
- **ECDSA**：椭圆曲线数字签名算法，使用 SHA1 哈希
- **实现**：基于 `cryptography` 的 EC 实现

---

## 6. API 接口参数说明

### 对称加密接口

| 接口 | 必填参数 | 可选参数 |
|------|----------|----------|
| `POST /api/aes/encrypt` | `data` | `key`, `mode` (默认 CBC) |
| `POST /api/aes/decrypt` | `data`, `key` | `iv`, `mode` |
| `POST /api/sm4/encrypt` | `data` | `key`, `mode` (默认 ECB) |
| `POST /api/sm4/decrypt` | `data`, `key` | `iv`, `mode` |
| `POST /api/rc6/encrypt` | `data` | `key`, `mode`, `rounds` (默认 20) |
| `POST /api/rc6/decrypt` | `data`, `key` | `iv`, `mode`, `rounds` |

### 哈希接口

| 接口 | 必填参数 | 可选参数 |
|------|----------|----------|
| `POST /api/<algo>/hash` | `data` | — |
| `POST /api/<algo>/hmac` | `key`, `data` | — |
| `POST /api/pbkdf2/derive` | `password` | `salt`, `iterations`, `key_len`, `hash_algo` |
| `POST /api/pbkdf2/verify` | `password`, `salt`, `derived_key` | `iterations`, `key_len`, `hash_algo` |

### 公钥密码接口

| 接口 | 必填参数 | 可选参数 |
|------|----------|----------|
| `POST /api/rsa/generate` | — | `key_size` |
| `POST /api/rsa/encrypt` | `data`, `public_key` | — |
| `POST /api/rsa/decrypt` | `data`, `private_key` | — |
| `POST /api/rsa/sign` | `data`, `private_key` | `hash_algo` |
| `POST /api/rsa/verify` | `data`, `signature`, `public_key` | `hash_algo` |
| `POST /api/ecc/generate` | — | `curve` |
| `POST /api/ecc/ecdh` | `own_private_key`, `peer_public_key` | — |
| `POST /api/ecdsa/sign` | `data`, `private_key` | — |
| `POST /api/ecdsa/verify` | `data`, `signature`, `public_key` | — |

### 统一返回格式

```json
{
  "status": "success",
  "message": "aes.encrypt 执行成功",
  "data": {
    "ciphertext": "...",
    "key": "...",
    "iv": "...",
    "mode": "CBC",
    "algorithm": "AES"
  }
}
```

---

## 7. 测试

### 7.1 运行 pytest 单元测试

```bash
# 运行全部测试
pytest tests/ -v

# 运行特定测试类
pytest tests/test_crypto.py::TestSymmetricCrypto -v
pytest tests/test_crypto.py::TestHashAlgorithms -v
pytest tests/test_crypto.py::TestAsymmetricCrypto -v
```

测试覆盖：
- AES 全部 5 种模式 + 自定义密钥 + 长文本
- SM4 ECB/CBC 模式
- RC6 ECB/CBC 模式 + 可变轮数(8/20) + 长文本 + CBC IV 随机性
- 所有哈希算法确定性 + 空输入
- HMAC 不同密钥产生不同结果
- PBKDF2 派生验证 + 错误密码拒绝 + 不同盐值产生不同密钥
- Base64 编码解码往返 + 空输入 + 二进制数据
- RSA 密钥生成 + 加密解密 + 签名验签 + 篡改检测
- ECC 密钥生成 + ECDH 共享密钥一致性 + ECDSA 签名验签 + 篡改检测
- CryptoAPI 无效算法错误处理 + 全部 handler 注册完整性

### 7.2 运行 API 测试客户端

```bash
# 先启动 API 服务（新终端窗口）
python api_server.py

# 再运行测试客户端
python test_client.py
```

测试客户端通过 HTTP 请求逐一验证所有 API 端点，检查加密/解密往返一致性、签名验签正确性、ECDH 共享密钥匹配。

---

## 8. 生成报告

```bash
python report_generator.py
```

脚本执行全部算法测试，收集结果，生成 `report.html`。在浏览器中打开该文件，`Ctrl+P` 即可打印/导出为 PDF。

---

## 9. 参考文献

1. NIST. FIPS 197: Advanced Encryption Standard (AES). 2001.
2. Rivest R L, et al. The RC6 Block Cipher. RSA Laboratories, 1998.
3. 国家密码管理局. GM/T 0002-2012 SM4 分组密码算法. 2012.
4. NIST. FIPS 180-4: Secure Hash Standard (SHS). 2015.
5. NIST. FIPS 202: SHA-3 Standard. 2015.
6. Dobbertin H, Bosselaers A, Preneel B. RIPEMD-160. 1996.
7. Krawczyk H, et al. RFC 2104: HMAC. 1997.
8. Kaliski B. RFC 2898: PKCS #5. 2000.
9. Josefsson S. RFC 4648: Base16, Base32, and Base64 Data Encodings. 2006.
10. Rivest R L, Shamir A, Adleman L. RSA. 1978.
11. NIST. FIPS 186-4: Digital Signature Standard. 2013.
12. Miller V S. Use of Elliptic Curves in Cryptography. CRYPTO 1985.
