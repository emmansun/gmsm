# 后量子密码（PQC）

## 概述

后量子密码（Post-Quantum Cryptography，PQC）是指能够抵御量子计算机攻击的密码算法。大型量子计算机可以利用 Shor 算法在多项式时间内破解当前广泛使用的基于 RSA、ECC（包括 SM2）的公钥密码体系，以及 "先收割后解密"（Harvest Now, Decrypt Later）攻击策略，对长期保密数据构成直接威胁。

NIST 于 2024 年发布后量子密码系列联邦标准：

- **FIPS 203**（ML-KEM）：基于模格学习误差（Module-LWE）的密钥封装机制，前身为 Kyber。
- **FIPS 204**（ML-DSA）：基于模格短整数解（Module-LWE/SIS）的数字签名方案，前身为 Dilithium。
- **FIPS 205**（SLH-DSA）：基于无状态哈希的数字签名方案，前身为 SPHINCS+。

GMSM 已实现以上全部三个标准，并提供了 X.509 证书、CMS（PKCS#7）和 TLS 1.3 中的集成支持。

---

## ML-KEM（FIPS 203）

ML-KEM 是一种密钥封装机制（Key Encapsulation Mechanism），用于在两个通信方之间安全地建立共享密钥。它包含三种安全级别的参数集：

| 参数集        | 安全级别 | 封装密钥大小 | 解封密钥大小 | 密文大小 | 共享密钥大小 |
|--------------|---------|------------|------------|---------|------------|
| ML-KEM-512   | 1（≈AES-128）| 800 字节   | 1632 字节  | 768 字节 | 32 字节    |
| ML-KEM-768   | 3（≈AES-192）| 1184 字节  | 2400 字节  | 1088 字节| 32 字节    |
| ML-KEM-1024  | 5（≈AES-256）| 1568 字节  | 3168 字节  | 1568 字节| 32 字节    |

对应 Go 包：`github.com/emmansun/gmsm/mlkem`

### 密钥生成

```go
import "github.com/emmansun/gmsm/mlkem"

// 随机生成解封密钥（内含封装密钥）
dk, err := mlkem.GenerateKey768(rand.Reader)

// 或从 64 字节种子 (d‖z) 确定性派生
seed := make([]byte, mlkem.SeedSize) // SeedSize = 64
rand.Read(seed)
dk, err = mlkem.NewDecapsulationKeyFromSeed768(seed)
```

### 密钥封装（发送方）

```go
// 从解封密钥获取封装密钥
ek := dk.EncapsulationKey()

// 封装：生成共享密钥和密文
sharedKey, ciphertext, err := ek.Encapsulate(rand.Reader)
// sharedKey: 32 字节，用于对称加密
// ciphertext: 传输给解封方
```

### 密钥解封（接收方）

```go
// 解封：从密文恢复共享密钥
sharedKey, err := dk.Decapsulate(ciphertext)
// sharedKey 与发送方生成的相同
```

### 序列化

```go
// 解封密钥
seed := dk.Seed()      // 64 字节种子（推荐存储方式）
expanded := dk.Bytes() // 完整展开格式

// 封装密钥（用于分发给对端）
ekBytes := dk.EncapsulationKey().Bytes()

// 从字节恢复封装密钥
ek, err = mlkem.NewEncapsulationKey768(ekBytes)
```

> **注意**：对于 ML-KEM-512 和 ML-KEM-1024，函数名中的 `768` 替换为 `512` 或 `1024`，API 完全对称。

---

## ML-DSA（FIPS 204）

ML-DSA 是一种数字签名方案，包含三种安全级别的参数集：

| 参数集    | 安全级别 | 公钥大小  | 私钥大小  | 签名大小  |
|----------|---------|---------|---------|---------|
| ML-DSA-44 | 2（≈AES-128）| 1312 字节 | 2560 字节 | 2420 字节 |
| ML-DSA-65 | 3（≈AES-192）| 1952 字节 | 4032 字节 | 3309 字节 |
| ML-DSA-87 | 5（≈AES-256）| 2592 字节 | 4896 字节 | 4627 字节 |

对应 Go 包：`github.com/emmansun/gmsm/mldsa`

### 密钥类型

每个参数集提供两个密钥类型族：

- **`Key44`**（`Key65`、`Key87`）：包含种子的组合密钥，实现 `crypto.Signer` 接口，推荐用于大多数场景。
- **`PrivateKey44`**（`PrivateKey65`、`PrivateKey87`）：展开格式的私钥，签名性能更高（无需每次从种子展开）。

### 密钥生成

```go
import "github.com/emmansun/gmsm/mldsa"

// 随机生成（返回 Key44，实现 crypto.Signer）
key, err := mldsa.GenerateKey44(rand.Reader)

// 从 32 字节种子确定性派生
seed := make([]byte, mldsa.SeedSize) // SeedSize = 32
rand.Read(seed)
key, err = mldsa.NewKey44(seed)

// 获取展开格式私钥（签名更快）
priv := key.PrivateKey()
```

### 签名

ML-DSA 支持两种签名模式：

**纯签名模式（推荐）**：直接对消息签名，无需预先哈希。

```go
opts := &mldsa.Options{} // 默认：纯签名，无上下文
sig, err := key.SignMessage(rand.Reader, message, opts)

// 带上下文的签名（上下文长度不超过 255 字节）
opts = &mldsa.Options{Context: []byte("my-protocol-context")}
sig, err = key.SignMessage(rand.Reader, message, opts)
```

**预哈希模式（HashML-DSA）**：兼容 `crypto.Signer` 接口，先对消息哈希再签名。

```go
// 设置预哈希算法 OID
opts = &mldsa.Options{
    PrehashOID: mldsa.OIDDigestAlgorithmSHA256,
}
// 传入原始消息（内部自动完成哈希）
sig, err = key.SignMessage(rand.Reader, message, opts)

// 支持的预哈希算法：
// mldsa.OIDDigestAlgorithmSHA256
// mldsa.OIDDigestAlgorithmSHA512
// mldsa.OIDDigestAlgorithmSHA3_256 / SHA3_384 / SHA3_512
// mldsa.OIDDigestAlgorithmSHAKE128 / SHAKE256
// mldsa.OIDDigestAlgorithmSM3
```

### 验签

```go
pk := key.Public().(*mldsa.PublicKey44)

// 与签名时使用相同的 opts
ok := pk.VerifyWithOptions(sig, message, opts)

// 从字节恢复公钥
pk, err = mldsa.NewPublicKey44(pkBytes)
```

### 序列化

```go
// Key44（含种子）
seedBytes := key.Seed()         // 32 字节，推荐存储方式
pk := key.Public().(*mldsa.PublicKey44)
pkBytes := pk.Bytes()           // 1312 字节

// 从字节恢复
key, err = mldsa.NewKey44(seedBytes)
pk, err  = mldsa.NewPublicKey44(pkBytes)

// PrivateKey44（展开格式）
privBytes := priv.Bytes()       // 2560 字节
priv, err  = mldsa.NewPrivateKey44(privBytes)
```

### crypto.Signer 兼容性

`Key44`、`Key65`、`Key87` 均实现 `crypto.Signer` 接口，可直接用于标准库 TLS、X.509 证书签名等场景：

```go
var signer crypto.Signer = key // Key44 实现 crypto.Signer
```

### X.509 证书集成（RFC 9881）

`smx509` 包支持在 X.509 证书中使用 ML-DSA。RFC 9881 定义了 ML-DSA 的 X.509 算法标识符。

| 算法       | SignatureAlgorithm 常量    | OID                              |
|-----------|---------------------------|----------------------------------|
| ML-DSA-44 | `smx509.MLDSA44` (100)    | 2.16.840.1.101.3.4.3.17          |
| ML-DSA-65 | `smx509.MLDSA65` (101)    | 2.16.840.1.101.3.4.3.18          |
| ML-DSA-87 | `smx509.MLDSA87` (102)    | 2.16.840.1.101.3.4.3.19          |

```go
import "github.com/emmansun/gmsm/smx509"

// 签发 ML-DSA-65 自签名证书
template := &smx509.Certificate{
    SerialNumber:          big.NewInt(1),
    Subject:               pkix.Name{CommonName: "ML-DSA Test"},
    NotBefore:             time.Now(),
    NotAfter:              time.Now().Add(365 * 24 * time.Hour),
    SignatureAlgorithm:    smx509.MLDSA65,
    PublicKeyAlgorithm:    smx509.PKMLDSA65,
}
key65, _ := mldsa.GenerateKey65(rand.Reader)
certDER, err := smx509.CreateCertificate(rand.Reader, template, template, key65.Public(), key65)
```

> **注意**：ML-DSA 为"纯"签名方案，X.509 集成中**不使用**预哈希（`crypto.Hash(0)`）。

### CMS（PKCS#7）集成（RFC 9882）

RFC 9882 定义了 ML-DSA 在 CMS（CryptographicMessageSyntax）中的使用方式，OID 与 RFC 9881 相同。

```go
import "github.com/emmansun/gmsm/pkcs7"

// 使用 ML-DSA 密钥签名
p7, err := pkcs7.NewSignedData(content)
err = p7.AddSigner(cert, key65, pkcs7.SignerInfoConfig{})
signedData, err := p7.Finish()

// 验签
p7, err = pkcs7.Parse(signedData)
err = p7.Verify()
```

---

## SLH-DSA（FIPS 205）

SLH-DSA 是一种基于哈希的无状态数字签名方案，安全性仅依赖哈希函数，对量子攻击的抵抗性更为保守。

### 参数集

SLH-DSA 提供 12 个标准参数集（SHA2 和 SHAKE 系列），以及本项目额外支持的 2 个 SM3 参数集：

| 参数集名称                | Go 变量                    | 安全级别 | 速度 | 公钥 | 私钥 | 签名   |
|--------------------------|---------------------------|---------|------|------|------|--------|
| SLH-DSA-SHA2-128s        | `SLHDSA128SmallSHA2`      | 1       | 慢   | 32   | 64   | 7856   |
| SLH-DSA-SHA2-128f        | `SLHDSA128FastSHA2`       | 1       | 快   | 32   | 64   | 17088  |
| SLH-DSA-SHA2-192s        | `SLHDSA192SmallSHA2`      | 3       | 慢   | 48   | 96   | 16224  |
| SLH-DSA-SHA2-192f        | `SLHDSA192FastSHA2`       | 3       | 快   | 48   | 96   | 35664  |
| SLH-DSA-SHA2-256s        | `SLHDSA256SmallSHA2`      | 5       | 慢   | 64   | 128  | 29792  |
| SLH-DSA-SHA2-256f        | `SLHDSA256FastSHA2`       | 5       | 快   | 64   | 128  | 49856  |
| SLH-DSA-SHAKE-128s       | `SLHDSA128SmallSHAKE`     | 1       | 慢   | 32   | 64   | 7856   |
| SLH-DSA-SHAKE-128f       | `SLHDSA128FastSHAKE`      | 1       | 快   | 32   | 64   | 17088  |
| SLH-DSA-SHAKE-192s       | `SLHDSA192SmallSHAKE`     | 3       | 慢   | 48   | 96   | 16224  |
| SLH-DSA-SHAKE-192f       | `SLHDSA192FastSHAKE`      | 3       | 快   | 48   | 96   | 35664  |
| SLH-DSA-SHAKE-256s       | `SLHDSA256SmallSHAKE`     | 5       | 慢   | 64   | 128  | 29792  |
| SLH-DSA-SHAKE-256f       | `SLHDSA256FastSHAKE`      | 5       | 快   | 64   | 128  | 49856  |
| SLH-DSA-SM3-128s ¹       | `SLHDSA128SmallSM3`       | 1       | 慢   | 32   | 64   | 7856   |
| SLH-DSA-SM3-128f ¹       | `SLHDSA128FastSM3`        | 1       | 快   | 32   | 64   | 17088  |

¹ SM3 参数集为本项目扩展，尚无标准 OID，不支持 X.509/CMS 集成。

**大小（Small/s）vs 快速（Fast/f）**：Small 参数集签名较小，但签名/验签速度较慢；Fast 参数集签名更大，但速度更快。

对应 Go 包：`github.com/emmansun/gmsm/slhdsa`

### 获取参数集

```go
import "github.com/emmansun/gmsm/slhdsa"

// 通过包级变量直接引用
params := &slhdsa.SLHDSA128SmallSHA2

// 通过名称查找
params, ok := slhdsa.GetParameterSet("SLH-DSA-SHA2-128s")

// 通过 OID 查找
params, ok = slhdsa.GetParameterSetByOID(oid)
```

### 密钥生成

```go
// 随机生成
sk, err := params.GenerateKey(rand.Reader)

// 获取公钥
pk := sk.Public().(*slhdsa.PublicKey)
// 或
pk = sk.PublicKey()
```

### 签名

SLH-DSA 同样支持纯签名和预哈希两种模式：

```go
// 纯签名（推荐）
opts := &slhdsa.Options{} // 默认纯签名
sig, err := sk.SignMessage(rand.Reader, message, opts)

// 带上下文
opts = &slhdsa.Options{Context: []byte("my-context")}
sig, err = sk.SignMessage(rand.Reader, message, opts)

// 预哈希模式（HashSLH-DSA）
opts = &slhdsa.Options{
    PrehashOID: slhdsa.OIDDigestAlgorithmSHA256, // 或其他支持的哈希
}
sig, err = sk.SignMessage(rand.Reader, message, opts)
```

### 验签

```go
ok := pk.VerifyWithOptions(sig, message, opts)
// opts 必须与签名时一致
```

### 序列化

```go
// 私钥
skBytes := sk.Bytes()              // 字节序列化
sk, err = params.NewPrivateKey(skBytes)

// 公钥
pkBytes := pk.Bytes()
pk, err = params.NewPublicKey(pkBytes)

// 获取参数集信息
paramSet := pk.ParameterSet()     // *slhdsa.ParameterSet
oid := pk.OID()                   // asn1.ObjectIdentifier（SM3 参数集返回 nil）
```

### X.509 证书集成（RFC 9909）

RFC 9909 定义了 12 个标准 SLH-DSA 参数集的 X.509 算法标识符。

| 参数集                   | SignatureAlgorithm 常量       | OID                           |
|--------------------------|------------------------------|-------------------------------|
| SLH-DSA-SHA2-128s        | `smx509.SLHDSASHA2128s` (110) | 2.16.840.1.101.3.4.3.20       |
| SLH-DSA-SHA2-128f        | `smx509.SLHDSASHA2128f` (111) | 2.16.840.1.101.3.4.3.21       |
| SLH-DSA-SHA2-192s        | `smx509.SLHDSASHA2192s` (112) | 2.16.840.1.101.3.4.3.22       |
| SLH-DSA-SHA2-192f        | `smx509.SLHDSASHA2192f` (113) | 2.16.840.1.101.3.4.3.23       |
| SLH-DSA-SHA2-256s        | `smx509.SLHDSASHA2256s` (114) | 2.16.840.1.101.3.4.3.24       |
| SLH-DSA-SHA2-256f        | `smx509.SLHDSASHA2256f` (115) | 2.16.840.1.101.3.4.3.25       |
| SLH-DSA-SHAKE-128s       | `smx509.SLHDSASHAKE128s` (116)| 2.16.840.1.101.3.4.3.26       |
| SLH-DSA-SHAKE-128f       | `smx509.SLHDSASHAKE128f` (117)| 2.16.840.1.101.3.4.3.27       |
| SLH-DSA-SHAKE-192s       | `smx509.SLHDSASHAKE192s` (118)| 2.16.840.1.101.3.4.3.28       |
| SLH-DSA-SHAKE-192f       | `smx509.SLHDSASHAKE192f` (119)| 2.16.840.1.101.3.4.3.29       |
| SLH-DSA-SHAKE-256s       | `smx509.SLHDSASHAKE256s` (120)| 2.16.840.1.101.3.4.3.30       |
| SLH-DSA-SHAKE-256f       | `smx509.SLHDSASHAKE256f` (121)| 2.16.840.1.101.3.4.3.31       |

```go
template := &smx509.Certificate{
    SignatureAlgorithm: smx509.SLHDSASHA2128s,
    PublicKeyAlgorithm: smx509.PKSLHDSASHA2128s,
    // ...
}
sk, _ := slhdsa.SLHDSA128SmallSHA2.GenerateKey(rand.Reader)
certDER, err := smx509.CreateCertificate(rand.Reader, template, template, sk.Public(), sk)
```

### CMS（PKCS#7）集成（RFC 9814）

RFC 9814 定义了 SLH-DSA 在 CMS 中的使用，与 X.509 使用相同的 OID。

```go
p7, err := pkcs7.NewSignedData(content)
err = p7.AddSigner(cert, sk, pkcs7.SignerInfoConfig{})
signedData, err := p7.Finish()
```

---

## TLS 1.3 混合密钥交换

在向后量子时代过渡期间，推荐使用"混合密钥交换"（Hybrid Key Exchange）：同时运行传统 ECDH 和 ML-KEM，只有两者同时被破解才能危及安全。

GMSM 的 `tls13` 包实现了 [draft-ietf-tls-hybrid-design](https://datatracker.ietf.org/doc/draft-ietf-tls-hybrid-design/) 的关键交换原语。

对应 Go 包：`github.com/emmansun/gmsm/tls13`

### 支持的命名组

| 命名组               | `CurveID` 常量          | 值      | 组成                        |
|---------------------|------------------------|---------|----------------------------|
| x25519              | `CurveX25519`          | 0x001D  | 纯 X25519                  |
| secp256r1           | `CurveP256`            | 0x0017  | 纯 P-256                   |
| secp384r1           | `CurveP384`            | 0x0018  | 纯 P-384                   |
| secp521r1           | `CurveP521`            | 0x0019  | 纯 P-521                   |
| curveSM2            | `CurveSM2`             | 0x0029  | 纯 SM2（RFC 8998）          |
| X25519MLKEM768      | `X25519MLKEM768`       | 0x11ec  | X25519 + ML-KEM-768        |
| SecP256r1MLKEM768   | `SecP256r1MLKEM768`    | 0x11eb  | P-256 + ML-KEM-768         |
| SecP384r1MLKEM1024  | `SecP384r1MLKEM1024`   | 0x11ed  | P-384 + ML-KEM-1024        |
| SM2MLKEM768 ²       | `SM2MLKEM768`          | 0x11ee  | SM2 + ML-KEM-768（扩展）   |

² `SM2MLKEM768` 为本项目扩展，尚未纳入 IETF 标准。

### 密钥共享数据格式

混合命名组的密钥共享数据由经典密钥共享和 ML-KEM 密钥共享拼接而成，拼接顺序由命名组决定：

| 命名组               | ClientHello 数据格式                      | ServerHello 数据格式                     |
|---------------------|------------------------------------------|------------------------------------------|
| X25519MLKEM768      | ML-KEM-768 封装密钥（1184 B）‖ X25519（32 B） | ML-KEM-768 密文（1088 B）‖ X25519（32 B） |
| SecP256r1MLKEM768   | P-256 点（65 B）‖ ML-KEM-768 封装密钥（1184 B）| P-256 点（65 B）‖ ML-KEM-768 密文（1088 B）|
| SecP384r1MLKEM1024  | P-384 点（97 B）‖ ML-KEM-1024 封装密钥（1568 B）| P-384 点（97 B）‖ ML-KEM-1024 密文（1568 B）|
| SM2MLKEM768         | SM2 点（65 B）‖ ML-KEM-768 封装密钥（1184 B）| SM2 点（65 B）‖ ML-KEM-768 密文（1088 B）|

共享密钥 = ECDH 共享密钥 ‖ ML-KEM 共享密钥（顺序与密钥共享数据格式一致）。

### 客户端流程

```go
import "github.com/emmansun/gmsm/tls13"

// 创建混合密钥交换对象
ke, err := tls13.NewKeyExchange(tls13.X25519MLKEM768)

// 生成 ClientHello 密钥共享
// clientKeyShares[0] 为混合密钥共享，clientKeyShares[1] 为纯 ECDH 后备
priv, clientKeyShares, err := ke.KeyShares(rand.Reader)

// 发送 clientKeyShares[0].Data 到服务器（在 ClientHello 中）
// 服务器响应包含 serverKeyShare

// 从服务器响应中计算共享密钥
sharedSecret, err := ke.ClientSharedSecret(priv, serverKeyShare.Data)
```

### 服务器端流程

```go
ke, err := tls13.NewKeyExchange(tls13.X25519MLKEM768)

// 从客户端密钥共享计算服务器共享密钥
sharedSecret, serverKeyShare, err := ke.ServerSharedSecret(rand.Reader, clientKeyShare)
// serverKeyShare.Data 放入 ServerHello 返回客户端
```

### 纯 ECDH 流程

```go
ke, err := tls13.NewKeyExchange(tls13.CurveP256)

// 客户端
priv, clientKeyShares, err := ke.KeyShares(rand.Reader)
// clientKeyShares[0].Data 为 P-256 公钥

// 服务器
sharedSecret, serverKeyShare, err := ke.ServerSharedSecret(rand.Reader, clientKeyShares[0].Data)

// 客户端完成
sharedSecret, err = ke.ClientSharedSecret(priv, serverKeyShare.Data)
```

---

## 参考规范

| 规范            | 内容                                              |
|----------------|--------------------------------------------------|
| NIST FIPS 203  | ML-KEM（Module-Lattice-Based Key-Encapsulation Mechanism）|
| NIST FIPS 204  | ML-DSA（Module-Lattice-Based Digital Signature Algorithm）|
| NIST FIPS 205  | SLH-DSA（Stateless Hash-Based Digital Signature Algorithm）|
| RFC 9881       | ML-DSA 在 X.509 公钥证书和证书吊销列表中的使用     |
| RFC 9882       | ML-DSA 在 CMS 中的使用                           |
| RFC 9909       | SLH-DSA 在 X.509 公钥证书和证书吊销列表中的使用   |
| RFC 9814       | SLH-DSA 在 CMS 中的使用                          |
| RFC 8998       | SM2 数字签名算法在 TLS 1.3 中的使用              |
| draft-ietf-tls-hybrid-design | TLS 1.3 混合密钥交换设计                |
