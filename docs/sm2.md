# SM2 椭圆曲线公钥密码算法应用指南

## 目录
- [标准与参考文献](#标准与参考文献)
- [概述](#概述)
- [密钥对管理](#密钥对管理)
- [数字签名](#数字签名)
- [密钥交换协议](#密钥交换协议)
- [公钥加密算法](#公钥加密算法)
- [KMS 集成](#kms-集成)
- [硬件密码模块集成](#硬件密码模块集成)
- [高级应用](#高级应用)

---

## 标准与参考文献

### 国家标准 (GB/T)
- **GB/T 32918.1-2016** - 信息安全技术 SM2椭圆曲线公钥密码算法 第1部分：总则
- **GB/T 32918.2-2016** - 信息安全技术 SM2椭圆曲线公钥密码算法 第2部分：数字签名算法
- **GB/T 32918.3-2016** - 信息安全技术 SM2椭圆曲线公钥密码算法 第3部分：密钥交换协议
- **GB/T 32918.4-2016** - 信息安全技术 SM2椭圆曲线公钥密码算法 第4部分：公钥加密算法
- **GB/T 32918.5-2017** - 信息安全技术 SM2椭圆曲线公钥密码算法 第5部分：参数定义
- **GB/T 35276-2017** - 信息安全技术 SM2密码算法使用规范
- **GB/T 33560-2017** - 信息安全技术 密码应用标识规范
- **GB/T 35275-2017** - 信息安全技术 SM2密码算法加密签名消息语法规范（等同于 PKCS#7）

### 行业标准 (GM/T)
- **GM/T 0091-2020** - 基于口令的密钥派生规范
- **GM/T 0092-2020** - 基于SM2算法的证书申请语法规范

### 相关标准
- **GB/T 36322-2018** - 密码设备应用接口规范（SDF API）
- **GB/T 35291-2017** - 智能密码钥匙应用接口规范（SKF API）

> 📖 **提示：** 可从[国家标准全文公开系统](https://openstd.samr.gov.cn/)在线阅读相关标准。

---

## 概述

### 算法对比

SM2是一种椭圆曲线公钥密码算法，与NIST P系列曲线（特别是P-256）相似。虽然NIST主要将ECDSA标准化用于签名，将ECDH用于密钥交换，但SM2提供了包括公钥加密在内的完整套件。下表对比了SM2与国际标准：

| **功能** | **SM2** | **NIST/SEC 1** |
|---------|---------|----------------|
| 数字签名 | SM2 签名算法 | ECDSA（[SEC 1](https://www.secg.org/sec1-v2.pdf)）|
| 密钥交换 | SM2 密钥交换协议 | ECMQV（[SEC 1](https://www.secg.org/sec1-v2.pdf)）|
| 公钥加密 | SM2 公钥加密算法 | ECIES（[SEC 1](https://www.secg.org/sec1-v2.pdf) 第5章）|

**关键差异：**
- **SM2 签名**：在哈希计算中包含用户标识符（UID）（Z值计算）
- **SM2 加密**：使用SM3哈希进行密钥派生函数（KDF），MAC方案与ECIES不同
- **SM2 密钥交换**：改进的MQV协议，包含基于身份的组件

### 安全背景

业界对RSA非对称加密安全性的担忧日益增加。椭圆曲线密码学以更小的密钥长度提供更好的安全边界：

- 🔒 [The Marvin Attack](https://people.redhat.com/~hkario/marvin/) - RSA PKCS#1 v1.5 时序攻击
- 🔒 [CVE-2023-45287](https://nvd.nist.gov/vuln/detail/CVE-2023-45287) - RSA 实现漏洞
- 🔒 [GO-2023-2375](https://pkg.go.dev/vuln/GO-2023-2375) - Go RSA 漏洞报告
- 📄 [Trail of Bits: Stop Using RSA](https://blog.trailofbits.com/2019/07/08/fuck-rsa/) - 业界立场文件

> ⚠️ **最佳实践：** 由于更好的安全边界、更小的密钥长度和改进的性能，现代应用应优先选择椭圆曲线密码学（ECC）而非RSA进行新实现。

---

## 密钥对管理

### 密钥对生成

使用 `sm2.GenerateKey()` 函数生成SM2密钥对：

```go
import (
    "crypto/rand"
    "github.com/emmansun/gmsm/sm2"
)

// 生成新的SM2密钥对
priv, err := sm2.GenerateKey(rand.Reader)
if err != nil {
    log.Fatalf("密钥对生成失败: %v", err)
}
```

**密钥类型结构：**

SM2私钥扩展了 `ecdsa.PrivateKey` 以实现SM2特定的方法：

```go
// PrivateKey 表示一个 ECDSA SM2 私钥。
// 它实现了 crypto.Decrypter 和 crypto.Signer 接口。
type PrivateKey struct {
    ecdsa.PrivateKey
    // 额外的 SM2 特定字段
}
```

SM2公钥使用标准的 `ecdsa.PublicKey` 结构。

> ⚠️ **重要提示：** 从Go v1.20开始，`ecdsa.PublicKey` 包含了一个 `ECDH()` 方法，该方法与SM2**不兼容**。对于SM2密钥，请使用 `sm2.PublicKeyToECDH()` 代替。

---

### 公钥解析与构造

#### 从 PEM 编码数据解析

公钥通常以PEM编码文本形式传输：

```go
import (
    "encoding/pem"
    "github.com/emmansun/gmsm/smx509"
)

func parsePublicKey(pemContent []byte) (*ecdsa.PublicKey, error) {
    block, _ := pem.Decode(pemContent)
    if block == nil {
        return nil, errors.New("PEM块解析失败")
    }
    
    pub, err := smx509.ParsePKIXPublicKey(block.Bytes)
    if err != nil {
        return nil, err
    }
    
    // 类型断言为 *ecdsa.PublicKey
    ecdsaPub, ok := pub.(*ecdsa.PublicKey)
    if !ok {
        return nil, errors.New("不是ECDSA公钥")
    }
    
    return ecdsaPub, nil
}
```

#### 从原始坐标构造

从非压缩点坐标构造公钥：

```go
func ExampleNewPublicKey() {
    // 非压缩点格式: 0x04 || X || Y
    keypoints, _ := hex.DecodeString(
        "048356e642a40ebd18d29ba3532fbd9f3bbee8f027c3f6f39a5ba2f870369f9988" +
        "981f5efe55d1c5cdf6c0ef2b070847a14f7fdf4272a8df09c442f3058af94ba1")
    
    pub, err := sm2.NewPublicKey(keypoints)
    if err != nil {
        log.Fatalf("公钥创建失败: %v", err)
    }
    
    // 通过序列化回去验证
    marshaled := elliptic.Marshal(sm2.P256(), pub.X, pub.Y)
    fmt.Printf("%x\n", marshaled)
    // Output: 048356e642a40ebd18d29ba3532fbd9f3bbee8f027c3f6f39a5ba2f870369f9988981f5efe55d1c5cdf6c0ef2b070847a14f7fdf4272a8df09c442f3058af94ba1
}
```

**替代方法：**
- `ecdh.P256().NewPublicKey()` - 仅支持非压缩格式
- 使用 `sm2.P256()` 曲线直接构造坐标

---

### 私钥解析与构造

#### 支持的封装格式

私钥可以封装在多种格式中。合适的解析方法取决于具体格式（[详细讨论](https://github.com/emmansun/gmsm/issues/104)）：

| **格式** | **解析方法** | **说明** |
|---------|-------------|---------|
| **RFC 5915 / SEC1** | `smx509.ParseSM2PrivateKey()` | 标准EC私钥格式 |
| **PKCS#8（未加密）** | `smx509.ParsePKCS8PrivateKey()` | 标准未加密私钥 |
| **PKCS#8（加密）** | `pkcs8.ParsePKCS8PrivateKeySM2()` | 处理加密和未加密 |
| **PKCS#12** | `github.com/emmansun/go-pkcs12` | Microsoft PFX格式 |
| **PKCS#7 / CMS** | `github.com/emmansun/gmsm/pkcs7` | 密码消息语法 |
| **CFCA 自定义** | `cfca.ParseSM2()` | CFCA特定的PKCS#12变体 |
| **GB/T 35276-2017** | `sm2.ParseEnvelopedPrivateKey()` | 信封私钥（CSR响应）|

> 📝 **提示：** PEM文件通常在第一行标明格式（例如 `-----BEGIN EC PRIVATE KEY-----`）。ASN.1编码的密钥需要通过OID检查来识别格式。

#### 解析示例

**PKCS#8 加密私钥：**

```go
import (
    "github.com/emmansun/gmsm/pkcs8"
)

func parseEncryptedPrivateKey(pemData []byte, password []byte) (*sm2.PrivateKey, error) {
    block, _ := pem.Decode(pemData)
    if block == nil {
        return nil, errors.New("PEM解码失败")
    }
    
    priv, err := pkcs8.ParsePKCS8PrivateKeySM2(block.Bytes, password)
    if err != nil {
        return nil, fmt.Errorf("私钥解析失败: %w", err)
    }
    
    return priv, nil
}
```

**GB/T 35276-2017 信封私钥：**

典型使用场景：CA证书响应包含签名证书、CA生成的加密私钥和加密证书：

```go
import (
    "github.com/emmansun/gmsm/sm2"
)

func parseEnvelopedPrivateKey(envelopedData []byte, decryptKey *sm2.PrivateKey) (*sm2.PrivateKey, error) {
    priv, err := sm2.ParseEnvelopedPrivateKey(envelopedData, decryptKey)
    if err != nil {
        return nil, fmt.Errorf("信封私钥解析失败: %w", err)
    }
    return priv, nil
}
```

#### 从原始字节构造

直接从标量字节构造私钥：

```go
func ExampleNewPrivateKey() {
    // 32字节标量形式的私钥
    keyBytes, _ := hex.DecodeString(
        "6c5a0a0b2eed3cbec3e4f1252bfe0e28c504a1c6bf1999eebb0af9ef0f8e6c85")
    
    priv, err := sm2.NewPrivateKey(keyBytes)
    if err != nil {
        log.Fatalf("私钥创建失败: %v", err)
    }
    
    fmt.Printf("%x\n", priv.D.Bytes())
    // Output: 6c5a0a0b2eed3cbec3e4f1252bfe0e28c504a1c6bf1999eebb0af9ef0f8e6c85
}

func ExampleNewPrivateKeyFromInt() {
    key := big.NewInt(0x123456)
    priv, err := sm2.NewPrivateKeyFromInt(key)
    if err != nil {
        log.Fatalf("私钥创建失败: %v", err)
    }
    
    fmt.Printf("%x\n", priv.D.Bytes())
    // Output: 123456
}
```

**替代方法：**
- `ecdh.P256().NewPrivateKey()` - 需要恰好32字节（必要时零填充）

---

### GM/T 0091-2020：基于口令的密钥派生

**GM/T 0091-2020** 本质上是 [RFC 8018 (PKCS#5)](https://datatracker.ietf.org/doc/html/rfc8018) 的中国定制版本，为 PBES/PBKDF/PBMAC 方案使用了不同的OID。然而，这些OID似乎未经注册，且标准本身存在不一致之处。

#### OID 定义

| **对象标识符** | **定义** |
|--------------|---------|
| `1.2.156.10197.6.1.4.1.5` | 基于口令的密钥派生规范 |
| `1.2.156.10197.6.1.4.1.5.1` | PBKDF（本质上是PBKDF2）|
| `1.2.156.10197.6.1.4.1.5.2` | PBES（本质上是PBES2）|
| `1.2.156.10197.6.1.4.1.5.3` | PBMAC（基于口令的MAC）|

#### 标准不一致性

1. **附录 A.2** 将 `id-hmacWithSM3` 定义为 `1.2.156.10197.1.401.3.1`（未注册）
2. **附录 A.4** 示例片段使用OID `1.2.156.10197.1.401`，暗示从PKCS#12-MAC复制粘贴而非PBMAC1
3. **附录 B.2** 引入 `pbeWithSM3AndSM4-CBC` 为 `1.2.156.10197.6.1.4.1.12.1.1`（暗示PBES1方法）
4. **附录 C** 将 `id-hmacWithSM3` 重新定义为 `1.2.156.10197.1.401.2`（与A.2矛盾）

> ⚠️ **兼容性警告：** 由于这些不一致性，与声称符合GM/T 0091-2020标准的产品进行互操作可能具有挑战性。常用的 `id-hmacWithSM3` OID 是 `1.2.156.10197.1.401.2`。

---

## 数字签名

### 标准签名

SM2签名通过 **Z** 值在哈希计算中包含用户标识符（UID）。标准UID是 `1234567812345678@`（默认值）。

#### 基本签名示例

```go
func ExamplePrivateKey_Sign() {
    toSign := []byte("ShangMi SM2 Sign Standard")
    
    // 加载或生成私钥
    privKey, _ := hex.DecodeString(
        "6c5a0a0b2eed3cbec3e4f1252bfe0e28c504a1c6bf1999eebb0af9ef0f8e6c85")
    testkey, err := sm2.NewPrivateKey(privKey)
    if err != nil {
        log.Fatalf("私钥创建失败: %v", err)
    }

    // 使用默认SM2选项签名（包含Z值计算）
    sig, err := testkey.Sign(rand.Reader, toSign, sm2.DefaultSM2SignerOpts)
    if err != nil {
        fmt.Fprintf(os.Stderr, "签名错误: %s\n", err)
        return
    }

    fmt.Printf("签名: %x\n", sig)
}
```

#### 自定义 UID 签名

对于非标准UID，创建自定义签名选项：

```go
import "github.com/emmansun/gmsm/sm2"

customUID := []byte("customUserID@domain.com")
signerOpts := sm2.NewSM2SignerOption(true, customUID)

sig, err := privateKey.Sign(rand.Reader, message, signerOpts)
```

#### SM2 特定签名方法

使用 `sm2.Signer` 接口的 `SignWithSM2` 方法进行显式SM2签名：

```go
sig, err := privateKey.SignWithSM2(rand.Reader, uid, message)
```

**接口对比：**
- `Sign()` - 来自 `crypto.Signer` 接口（标准Go密码学）
- `SignWithSM2()` - 来自 `sm2.Signer` 接口（SM2特定）

---

### 签名验证

使用 `sm2.VerifyASN1WithSM2()` 验证SM2签名：

```go
func ExampleVerifyASN1WithSM2() {
    // 解析或构造公钥
    keypoints, _ := hex.DecodeString(
        "048356e642a40ebd18d29ba3532fbd9f3bbee8f027c3f6f39a5ba2f870369f9988" +
        "981f5efe55d1c5cdf6c0ef2b070847a14f7fdf4272a8df09c442f3058af94ba1")
    publicKey, err := sm2.NewPublicKey(keypoints)
    if err != nil {
        log.Fatalf("公钥创建失败: %v", err)
    }

    message := []byte("ShangMi SM2 Sign Standard")
    signature, _ := hex.DecodeString(
        "304402205b3a799bd94c9063120d7286769220af6b0fa127009af3e873c0e8742edc5f89" +
        "0220097968a4c8b040fd548d1456b33f470cabd8456bfea53e8a828f92f6d4bdcd77")

    // 使用默认UID验证（nil = 使用默认值）
    valid := sm2.VerifyASN1WithSM2(publicKey, nil, message, signature)

    fmt.Printf("签名有效: %v\n", valid)
    // Output: 签名有效: true
}
```

**自定义 UID 验证：**

```go
customUID := []byte("customUserID@domain.com")
valid := sm2.VerifyASN1WithSM2(publicKey, customUID, message, signature)
```

---

### 不使用 Z 值的签名

为了与期望ECDSA风格签名（无Z值计算）的系统兼容：

#### 签名

```go
// 自己预先计算哈希
hash := sm3.Sum(message)

// 直接对哈希签名（无Z值）
sig, err := privateKey.Sign(rand.Reader, hash[:], nil)
```

> 📝 **提示：** 当 `SignerOpts` 为 `nil` 或不是 `SM2SignerOption` 时，输入被视为预计算的哈希，不进行Z值计算。

#### 验证

```go
// 自己预先计算哈希（必须与签名时的哈希算法匹配）
hash := sm3.Sum(message)

// 不使用Z值验证
valid := sm2.VerifyASN1(publicKey, hash[:], signature)
```

> ⚠️ **重要提示：** 确保签名和验证使用的哈希算法相同。

---

### 大文件签名

对于大文件，对哈希而非整个文件进行签名：

```go
import (
    "github.com/emmansun/gmsm/sm3"
    "io"
)

func signLargeFile(file io.Reader, privateKey *sm2.PrivateKey, uid []byte) ([]byte, error) {
    // 计算 Z 值
    za, err := sm2.CalculateZA(privateKey.Public().(*ecdsa.PublicKey), uid)
    if err != nil {
        return nil, err
    }
    
    // 使用预先添加的 Z 值对文件进行哈希
    h := sm3.New()
    h.Write(za)
    if _, err := io.Copy(h, file); err != nil {
        return nil, err
    }
    hash := h.Sum(nil)
    
    // 对哈希签名
    return privateKey.Sign(rand.Reader, hash, nil)
}
```

> 💡 **提示：** 从 v0.24.0 开始，使用 `sm2.CalculateSM2Hash()` 方便地进行包含Z值的哈希计算。

---

## 密钥交换协议

SM2密钥交换协议在两个包中可用：

### 实现对比

| **包** | **说明** | **使用场景** |
|-------|---------|-------------|
| `sm2` | 传统实现 | 遗留兼容性 |
| `ecdh` | 现代Go风格实现 | 新应用、TLS/TLCP |

两种实现都提供安全的密钥协商功能。`ecdh` 包遵循Go的现代密码学API设计模式。

> 📖 **参考：** 实际使用示例请参见 [gotlcp](https://github.com/Trisia/gotlcp) TLS/TLCP实现。

> ⚠️ **提示：** 密钥交换协议主要用于TLS/TLCP上下文。大多数应用层开发不需要直接使用密钥交换协议。

---

## 公钥加密算法

### 概述

> ⚠️ **重要原则：** 非对称加密**不是**为加密大量数据而设计的。它应该用于加密对称密钥，然后用对称密钥加密实际数据。这种模式用于：
> - **TLS/TLCP**：加密会话密钥
> - **信封加密**：加密数据加密密钥（DEK）

### 密文编码格式

SM2公钥加密支持两种密文格式：

| **格式** | **说明** | **结构** |
|---------|---------|---------|
| **ASN.1** | 标准编码 | ASN.1 DER结构 |
| **简单串接** | 简单字节串接 | C1‖C3‖C2（当前标准）或 C1‖C2‖C3（遗留）|

**格式组成：**
- **C1**：临时公钥点（椭圆曲线点）
- **C2**：加密消息
- **C3**：消息认证码（MAC）

> 📝 **历史说明：** 2010年标准使用 C1‖C2‖C3 格式。2012年标准（GM/T 0003-2012）改为 C1‖C3‖C2，并在GB/T 32918-2016中得以维持。

---

### 加密

#### ASN.1 格式加密

```go
func ExampleEncryptASN1() {
    // 解析或加载公钥
    keypoints, _ := hex.DecodeString(
        "048356e642a40ebd18d29ba3532fbd9f3bbee8f027c3f6f39a5ba2f870369f9988" +
        "981f5efe55d1c5cdf6c0ef2b070847a14f7fdf4272a8df09c442f3058af94ba1")
    publicKey, err := sm2.NewPublicKey(keypoints)
    if err != nil {
        log.Fatalf("公钥创建失败: %v", err)
    }

    plaintext := []byte("send reinforcements, we're going to advance")

    // 使用 ASN.1 格式加密
    ciphertext, err := sm2.EncryptASN1(rand.Reader, publicKey, plaintext)
    if err != nil {
        fmt.Fprintf(os.Stderr, "加密错误: %s\n", err)
        return
    }

    fmt.Printf("密文 (ASN.1): %x\n", ciphertext)
}
```

#### 简单串接格式加密

```go
// 使用简单串接加密（默认 C1C3C2）
ciphertext, err := sm2.Encrypt(rand.Reader, publicKey, plaintext, nil)
if err != nil {
    fmt.Fprintf(os.Stderr, "加密错误: %s\n", err)
    return
}

fmt.Printf("密文 (C1C3C2): %x\n", ciphertext)
```

> 📝 **提示：** 将 `EncrypterOpts` 传递为 `nil` 默认使用 C1‖C3‖C2 格式。

---

### 解密

SM2私钥的 `Decrypt()` 方法自动检测密文格式：

```go
func ExamplePrivateKey_Decrypt() {
    ciphertext, _ := hex.DecodeString(
        "308194022100bd31001ce8d39a4a0119ff96d71334cd12d8b75bbc780f5bfc6e1efab535e85a" +
        "02201839c075ff8bf761dcbe185c9750816410517001d6a130f6ab97fb23337cce1504" +
        "20ea82bd58d6a5394eb468a769ab48b6a26870ca075377eb06663780c920ea5ee00" +
        "42be22abcf48e56ae9d29ac770d9de0d6b7094a874a2f8d26c26e0b1daaf4ff50a484b88163d04785b04585bb")

    // 加载私钥
    privKey, _ := hex.DecodeString(
        "6c5a0a0b2eed3cbec3e4f1252bfe0e28c504a1c6bf1999eebb0af9ef0f8e6c85")
    privateKey, err := sm2.NewPrivateKey(privKey)
    if err != nil {
        log.Fatalf("私钥创建失败: %v", err)
    }

    // 解密（自动检测 ASN.1 或 C1C3C2 格式）
    plaintext, err := privateKey.Decrypt(nil, ciphertext, nil)
    if err != nil {
        fmt.Fprintf(os.Stderr, "解密错误: %s\n", err)
        return
    }

    fmt.Printf("明文: %s\n", string(plaintext))
    // Output: 明文: send reinforcements, we're going to advance
}
```

**遗留 C1C2C3 格式：**

对于遗留的 C1‖C2‖C3 密文，显式指定格式：

```go
import "github.com/emmansun/gmsm/sm2"

// 指定 C1C2C3 格式
opts := &sm2.DecrypterOpts{
    CiphertextEncoding: sm2.C1C2C3,
}

plaintext, err := privateKey.Decrypt(nil, ciphertext, opts)
```

**替代方法：** 使用辅助函数在解密前转换密文格式。

---

### 密文格式转换

`sm2` 包提供格式转换的实用函数：

#### ASN.1 ↔ 简单串接

```go
import "github.com/emmansun/gmsm/sm2"

// ASN.1 转简单串接（C1C3C2）
plainCiphertext, err := sm2.ASN1Ciphertext2Plain(asn1Ciphertext, nil)

// 简单串接转 ASN.1
asn1Ciphertext, err := sm2.PlainCiphertext2ASN1(plainCiphertext, sm2.C1C3C2)
```

#### 更改串接顺序

```go
// 在 C1C2C3 和 C1C3C2 之间转换
convertedCiphertext, err := sm2.AdjustCiphertextSplicingOrder(
    ciphertext,
    sm2.C1C2C3, // 源格式
    sm2.C1C3C2, // 目标格式
)
```

---

### 技术背景

#### 点到字节串的转换

所有SM2标准（从2010年密码管理局版本到GB/T 32918-2016）都在第1部分第4章中一致定义了点到字节串的转换。这遵循 [SEC 1: Elliptic Curve Cryptography (Version 2.0)](https://www.secg.org/sec1-v2.pdf) 第2.3.3节规范。

**标准格式：**
- **非压缩**：`0x04 || X || Y`（SM2为65字节）
- **压缩**：`0x02 || X` 或 `0x03 || X`（SM2为33字节）
- **混合**（罕见）：`0x06 || X || Y` 或 `0x07 || X || Y`

> ⚠️ **说明：** 一些实现使用固定的64字节表示（省略格式指示符）。这是**非标准**的，会导致互操作性问题。请始终遵循SEC 1规范进行正确编码。

#### 为什么一些实现省略格式指示符

**省略的原因：**
1. **简化**：降低实现复杂度
2. **假定知识**：封闭系统中的所有点使用相同格式
3. **遗留兼容性**：旧系统可能不支持多种格式
4. **误解**：对标准的错误理解

**后果：**
- ❌ **破坏互操作性**：期望格式指示符的系统无法解析数据
- ❌ **安全风险**：点表示的歧义可能导致验证失败
- ❌ **不合规**：违反SEC 1和GB/T 32918标准

> ✅ **最佳实践：** 始终按照SEC 1的规定包含格式指示符。为了最大兼容性，使用非压缩格式（`0x04`）并正确编码。

---

### 性能优化

从 **v0.27.0** 开始，对大数据加密/解密实施了显著的性能改进：

**优化项：**
- ✅ 密钥派生的并行KDF计算
- ✅ 优化的哈希操作
- ✅ 改进的内存分配策略

详细基准测试和性能分析请参考 [SM2加密/解密性能](https://github.com/emmansun/gmsm/wiki/SM2%E5%8A%A0%E8%A7%A3%E5%AF%86%E6%80%A7%E8%83%BD)。

> 📊 **性能提示：** 对于加密大量数据，使用信封加密（SM2加密对称密钥，然后使用SM4加密实际数据）。

---

## KMS 集成

### 概述

中国主要云服务提供商提供SM2密钥管理服务。典型集成模式：

| **操作** | **位置** | **密钥类型** |
|---------|---------|------------|
| **签名** | KMS API调用 | 私钥（在KMS中）|
| **验证** | 本地 | 公钥 |
| **加密** | 本地 | 公钥 |
| **解密** | KMS API调用 | 私钥（在KMS中）|

### KMS 签名的哈希计算

大多数KMS服务要求对预哈希数据进行签名。SM2签名需要包含 **Z** 值的特殊哈希计算：

#### 计算 SM2 哈希

```go
import (
    "github.com/emmansun/gmsm/sm2"
    "github.com/emmansun/gmsm/sm3"
)

func calculateSM2HashForKMS(pub *ecdsa.PublicKey, data, uid []byte) ([]byte, error) {
    // 如果未指定，使用默认UID
    if len(uid) == 0 {
        uid = []byte("1234567812345678")
    }
    
    // 计算 ZA（Z值）
    za, err := sm2.CalculateZA(pub, uid)
    if err != nil {
        return nil, err
    }
    
    // 哈希: SM3(ZA || message)
    h := sm3.New()
    h.Write(za)
    h.Write(data)
    return h.Sum(nil), nil
}
```

> 💡 **便捷函数：** 从 v0.24.0 开始，直接使用 `sm2.CalculateSM2Hash()`：

```go
hash, err := sm2.CalculateSM2Hash(publicKey, data, uid)
```

### KMS 加密

公钥加密很简单 - 确保密文编码与KMS要求匹配：

```go
// 大多数 KMS 服务使用 ASN.1 格式
ciphertext, err := sm2.EncryptASN1(rand.Reader, publicKey, plaintext)
if err != nil {
    return nil, fmt.Errorf("加密失败: %w", err)
}

// 将密文发送到 KMS 进行解密
```

### KMS 集成最佳实践

1. **缓存公钥**：一次性检索公钥并在本地缓存
2. **最小化 KMS 调用**：仅在需要私钥的操作中使用KMS
3. **错误处理**：为临时KMS API故障实现重试逻辑
4. **密钥轮换**：设计系统以无缝处理密钥轮换
5. **审计日志**：记录所有KMS操作以进行安全审计

---

## 硬件密码模块集成

### 概述

硬件密码模块（HSM）通常实现SDF（安全设备框架）或SKF（智能密钥框架）API。HSM中的私钥是**不可导出**的，但通过API提供签名和解密操作。

要与GMSM库集成，需要实现以下Go密码学接口：

### 必需接口

#### 1. `crypto.Signer` 接口

```go
type Signer interface {
    // Public 返回与私钥对应的公钥
    Public() crypto.PublicKey
    
    // Sign 使用私钥对摘要进行签名
    // 对于 SM2：摘要通常是预计算的哈希或原始消息
    Sign(rand io.Reader, digest []byte, opts SignerOpts) (signature []byte, err error)
}
```

#### 2. `crypto.Decrypter` 接口

```go
type Decrypter interface {
    // Public 返回与私钥对应的公钥
    Public() crypto.PublicKey
    
    // Decrypt 使用私钥解密消息
    Decrypt(rand io.Reader, msg []byte, opts DecrypterOpts) (plaintext []byte, err error)
}
```

### 实现指南

#### Public() 方法

```go
func (h *HSMPrivateKey) Public() crypto.PublicKey {
    // 返回与此私钥关联的公钥
    // 应从HSM检索或在初始化期间存储
    return h.publicKey
}
```

#### Sign() 方法

```go
func (h *HSMPrivateKey) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
    // 检查 opts 是否为 SM2 特定类型
    if sm2Opts, ok := opts.(*sm2.SM2SignerOption); ok && sm2Opts.ForceGMSign {
        // 将 digest 视为原始消息，计算 SM2 哈希
        hash, err := sm2.CalculateSM2Hash(
            h.Public().(*ecdsa.PublicKey),
            digest,
            sm2Opts.UID,
        )
        if err != nil {
            return nil, err
        }
        
        // 调用 HSM API 对哈希签名
        return h.hsmSignHash(hash)
    }
    
    // 将 digest 视为预计算的哈希
    return h.hsmSignHash(digest)
}

func (h *HSMPrivateKey) hsmSignHash(hash []byte) ([]byte, error) {
    // 调用 SDF/SKF API 执行签名
    // 示例: SDF_InternalSign_ECC(sessionHandle, keyIndex, hash)
    return h.sdkClient.Sign(h.keyHandle, hash)
}
```

**重要考虑事项：**

1. **哈希处理**：大多数HSM API期望哈希值。对于SM2：
   - 如果 `opts` 是 `*sm2.SM2SignerOption`，计算SM2哈希（包含Z值）
   - 否则，按原样使用摘要（预计算的哈希）

2. **随机数源**：HSM通常有硬件随机数生成器。可以忽略 `rand` 参数。

3. **错误处理**：将HSM特定错误映射到Go错误类型。

#### Decrypt() 方法

```go
func (h *HSMPrivateKey) Decrypt(rand io.Reader, msg []byte, opts crypto.DecrypterOpts) ([]byte, error) {
    // 调用 SDF/SKF API 执行解密
    // 示例: SDF_InternalDecrypt_ECC(sessionHandle, keyIndex, ciphertext)
    
    plaintext, err := h.sdkClient.Decrypt(h.keyHandle, msg)
    if err != nil {
        return nil, fmt.Errorf("HSM解密失败: %w", err)
    }
    
    return plaintext, nil
}
```

### 完整示例

```go
package hsm

import (
    "crypto"
    "crypto/ecdsa"
    "io"
    
    "github.com/emmansun/gmsm/sm2"
)

// HSMPrivateKey 表示存储在 HSM 中的私钥
type HSMPrivateKey struct {
    keyHandle  int                // HSM 密钥句柄/索引
    publicKey  *ecdsa.PublicKey   // 关联的公钥
    sdkClient  *SDFClient         // SDF/SKF SDK 客户端
}

// 编译时确保接口合规
var (
    _ crypto.Signer    = (*HSMPrivateKey)(nil)
    _ crypto.Decrypter = (*HSMPrivateKey)(nil)
)

func (h *HSMPrivateKey) Public() crypto.PublicKey {
    return h.publicKey
}

func (h *HSMPrivateKey) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
    var hash []byte
    
    // 检查是否为 SM2 特定签名
    if sm2Opts, ok := opts.(*sm2.SM2SignerOption); ok && sm2Opts.ForceGMSign {
        // 计算 SM2 哈希（ZA || 消息）
        var err error
        hash, err = sm2.CalculateSM2Hash(h.publicKey, digest, sm2Opts.UID)
        if err != nil {
            return nil, err
        }
    } else {
        // 按原样使用摘要（假定为预计算的哈希）
        hash = digest
    }
    
    // 调用 HSM 签名函数
    signature, err := h.sdkClient.InternalSign(h.keyHandle, hash)
    if err != nil {
        return nil, err
    }
    
    return signature, nil
}

func (h *HSMPrivateKey) Decrypt(rand io.Reader, msg []byte, opts crypto.DecrypterOpts) ([]byte, error) {
    plaintext, err := h.sdkClient.InternalDecrypt(h.keyHandle, msg)
    if err != nil {
        return nil, err
    }
    
    return plaintext, nil
}
```

### SDF/SKF API 参考

**SDF (GB/T 36322-2018)**：安全设备框架
- `SDF_OpenDevice` - 打开设备会话
- `SDF_InternalSign_ECC` - 内部密钥签名
- `SDF_InternalDecrypt_ECC` - 内部密钥解密
- `SDF_ExportSignPublicKey_ECC` - 导出公钥

**SKF (GB/T 35291-2017)**：智能密钥框架
- `SKF_ConnectDev` - 连接到设备
- `SKF_ECCSignData` - 使用ECC密钥签名数据
- `SKF_DecryptData` - 解密数据

> 📖 **标准**：完整的SDF API文档请参考GB/T 36322-2018（密码设备应用接口规范）。

---

## 高级应用

SM2椭圆曲线密码学支持各种高级密码协议。虽然其中一些处于概念验证阶段，没有正式标准，但它们展示了椭圆曲线密码学的多功能性。

### 可用扩展

#### 1. 从签名恢复公钥

ECDSA签名（包括SM2）由两个整数组成：**r** 和 **s**。以太坊引入了额外的变量 **v**（恢复标识符），使签名成为 {r, s, v}。由于SM2签名仅使用随机点的X坐标（对N取模），可以从签名恢复多个公钥。

```go
// RecoverPublicKeysFromSM2Signature 从给定的签名和哈希恢复两个或四个 SM2 公钥
func RecoverPublicKeysFromSM2Signature(hash, sig []byte) ([]*ecdsa.PublicKey, error)
```

**恢复的公钥：**
- **公钥 0**：Rx = (r - e) mod N; Ry为偶数（compressFlag = 2）
- **公钥 1**：Rx = (r - e) mod N; Ry为奇数（compressFlag = 3）
- **公钥 2**：Rx = ((r - e) mod N) + N; Ry为偶数（compressFlag = 2）*（罕见）*
- **公钥 3**：Rx = ((r - e) mod N) + N; Ry为奇数（compressFlag = 3）*（罕见）*

> 📝 **提示：** 通常只返回前两个公钥。后两个仅在 `(r - e) mod N < P - 1 - N` 时存在。

**使用场景：**
- **地址恢复**：无需传输公钥即可验证身份
- **紧凑签名**：在空间受限环境中减少签名大小
- **区块链应用**：类似以太坊的签名恢复

---

#### 2. 部分同态加密（EC-ElGamal）

基于SM2曲线的EC-ElGamal提供**部分同态加密**，支持对加密数据进行加法操作。

**支持类型：**
- `uint32` - 无符号32位整数
- `int32` - 有符号32位整数

**性质：**
- ✅ **加法同态**：`E(a) + E(b) = E(a + b)`
- ✅ **标量乘法**：`k * E(a) = E(k * a)`
- ❌ **范围受限**：由于离散对数计算，实际适用于小值

**实现：** [github.com/emmansun/sm2elgamal](https://github.com/emmansun/sm2elgamal)

**示例使用场景：**
```go
// 电子投票：无需解密即可累加加密的投票
encryptedVote1 := Encrypt(publicKey, 1)  // 投票 "赞成"
encryptedVote2 := Encrypt(publicKey, 0)  // 投票 "反对"
encryptedTotal := Add(encryptedVote1, encryptedVote2)
totalVotes := Decrypt(privateKey, encryptedTotal) // 结果: 1
```

---

#### 3. 环签名

环签名在群组内提供**签名者匿名性**。环中的任何人都可能产生该签名，但实际签名者保持匿名。

**性质：**
- ✅ **无条件匿名性**：即使是计算无界的对手也无法确定签名者
- ✅ **无群组管理者**：不需要可信第三方
- ✅ **自发群组**：可以在无需成员合作的情况下临时形成环

**实现：** [github.com/emmansun/sm2rsign](https://github.com/emmansun/sm2rsign)

**使用场景：**
- **举报**：匿名但经过身份验证的披露
- **机密交易**：保护隐私的区块链交易
- **匿名认证**：证明成员身份而不透露身份

---

### 其他潜在扩展

虽然尚未实现，但SM2理论上可以支持：

#### 确定性签名
- **标准**：[RFC 6979](https://datatracker.ietf.org/doc/html/rfc6979)
- **优势**：消除对安全随机数生成的依赖
- **使用场景**：熵源较差的嵌入式系统

#### 可验证随机函数（VRF）
- **标准**：[IETF CFRG VRF](https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-vrf-04)
- **性质**：具有可公开验证证明的伪随机输出
- **使用场景**：区块链共识、彩票系统

#### 盲签名
- **性质**：签名者在不查看消息内容的情况下签名
- **使用场景**：数字现金、保护隐私的凭证

#### 门限签名
- **性质**：需要多方合作才能创建签名
- **使用场景**：多方授权、分布式密钥管理

#### Pedersen 承诺
- **参考**：[Cryptography Stack Exchange](https://crypto.stackexchange.com/questions/64437/what-is-a-pedersen-commitment)
- **性质**：承诺值而不透露它，具有绑定和隐藏性质
- **使用场景**：零知识证明、机密交易

---

### 实现状态

| **扩展** | **状态** | **代码库** |
|---------|---------|-----------|
| 公钥恢复 | ✅ 已实现 | GMSM核心库 |
| EC-ElGamal PHE | ✅ POC可用 | [sm2elgamal](https://github.com/emmansun/sm2elgamal) |
| 环签名 | ✅ POC可用 | [sm2rsign](https://github.com/emmansun/sm2rsign) |
| 确定性签名 | ⏳ 计划中 | - |
| ECVRF | ⏳ 计划中 | - |
| 盲签名 | ⏳ 研究中 | - |
| 门限签名 | ⏳ 研究中 | - |
| Pedersen承诺 | ⏳ 研究中 | - |

> ⚠️ **提示：** 标记为POC（概念验证）的扩展是实验性的，缺乏正式标准。在没有彻底安全审查的情况下，不应在生产环境中使用。

---

## API 参考

完整的API文档请访问：[GMSM API 文档](https://godoc.org/github.com/emmansun/gmsm)

### 快速链接

- **SM2 包**：[godoc.org/github.com/emmansun/gmsm/sm2](https://godoc.org/github.com/emmansun/gmsm/sm2)
- **ECDH 包**：[godoc.org/github.com/emmansun/gmsm/ecdh](https://godoc.org/github.com/emmansun/gmsm/ecdh)
- **SMX509 包**：[godoc.org/github.com/emmansun/gmsm/smx509](https://godoc.org/github.com/emmansun/gmsm/smx509)
- **PKCS8 包**：[godoc.org/github.com/emmansun/gmsm/pkcs8](https://godoc.org/github.com/emmansun/gmsm/pkcs8)

---

## 其他资源

### 性能分析
- [SM2性能优化](https://github.com/emmansun/gmsm/wiki/SM2%E6%80%A7%E8%83%BD%E4%BC%98%E5%8C%96)
- [SM2加密/解密性能](https://github.com/emmansun/gmsm/wiki/SM2%E5%8A%A0%E8%A7%A3%E5%AF%86%E6%80%A7%E8%83%BD)
- [常量时间实现](https://github.com/emmansun/gmsm/wiki/is-my-code-constant-time%3F)

### 相关项目
- [TLCP 实现](https://github.com/Trisia/gotlcp) - GB/T 38636-2020 传输层密码协议
- [支持SM的PKCS#12](https://github.com/emmansun/go-pkcs12) - 支持SM的PKCS#12库
- [SM2的mkcert](https://github.com/emmansun/mksmcert) - 开发证书生成工具

### 标准文档
- [国家标准全文公开系统](https://openstd.samr.gov.cn/)
- [SEC 1: Elliptic Curve Cryptography](https://www.secg.org/sec1-v2.pdf)
- [RFC 8018: PKCS #5](https://datatracker.ietf.org/doc/html/rfc8018)

---

## 常见问题

### 问：新应用应该使用 SM2 还是 RSA？

**答：** 对于新的中国国内应用，推荐使用SM2，原因如下：
- ✅ 符合中国密码法规要求
- ✅ 更小的密钥长度（256位SM2 ≈ 3072位RSA安全性）
- ✅ 签名和密钥交换性能更好
- ✅ 中国证书颁发机构的原生支持

对于国际应用，考虑使用NIST P-256或Ed25519以获得更广泛的兼容性。

---

### 问：SM2 密钥可以与 ECDSA 一起使用吗？

**答：** **不可以。** SM2和ECDSA虽然都是椭圆曲线算法，但**不兼容**：
- 签名算法不同（SM2包含Z值）
- 曲线不同（SM2使用sm2p256v1，而非secp256r1）
- 哈希算法不同（SM3 vs SHA-256）

尝试将SM2密钥与ECDSA一起使用将导致无效签名。

---

### 问：如何处理 SM2 签名中的 Z 值？

**答：** Z值由库自动处理：
- **默认 UID**：`"1234567812345678"`（16字节）
- **自定义 UID**：使用 `sm2.NewSM2SignerOption(true, customUID)`
- **无 Z 值**：传递 `nil` 作为 `SignerOpts` 进行仅哈希签名

对于KMS集成，使用 `sm2.CalculateSM2Hash()` 计算包含Z值的哈希。

---

### 问：C1C2C3 和 C1C3C2 有什么区别？

**答：** 这些是SM2密文的不同串接顺序：
- **C1C2C3**：遗留格式（2010年标准）
- **C1C3C2**：当前格式（2012年以后标准）

库在解密期间自动检测格式。对于新实现，使用C1C3C2或ASN.1格式。

---

### 问：如何使用 SM2 加密大文件？

**答：** **不要直接使用SM2加密大文件。** 使用信封加密：

1. 生成随机对称密钥（例如，SM4 256位）
2. 使用SM4加密文件
3. 使用SM2公钥加密SM4密钥
4. 存储加密文件和加密密钥

这种方法更快、更安全，并遵循行业最佳实践。

---

## 许可证

本文档是GMSM项目的一部分，采用MIT许可证。详见主[LICENSE](../LICENSE)文件。
