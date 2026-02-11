# Go语言商用密码软件

[![Github CI](https://github.com/emmansun/gmsm/actions/workflows/ci.yml/badge.svg)](https://github.com/emmansun/gmsm/actions/workflows/ci.yml)
[![arm64](https://github.com/emmansun/gmsm/actions/workflows/test_qemu.yml/badge.svg)](https://github.com/emmansun/gmsm/actions/workflows/test_qemu.yml)
[![sm3-sm4-ni](https://github.com/emmansun/gmsm/actions/workflows/test_sm_ni.yml/badge.svg)](https://github.com/emmansun/gmsm/actions/workflows/test_sm_ni.yml)
[![riscv64](https://github.com/emmansun/gmsm/actions/workflows/test_riscv64.yaml/badge.svg)](https://github.com/emmansun/gmsm/actions/workflows/test_riscv64.yaml)
[![loong64](https://github.com/emmansun/gmsm/actions/workflows/test_loong64.yml/badge.svg)](https://github.com/emmansun/gmsm/actions/workflows/test_loong64.yml)
[![ppc64le](https://github.com/emmansun/gmsm/actions/workflows/test_ppc64.yaml/badge.svg)](https://github.com/emmansun/gmsm/actions/workflows/test_ppc64.yaml)
[![s390x](https://github.com/emmansun/gmsm/actions/workflows/test_s390x.yaml/badge.svg)](https://github.com/emmansun/gmsm/actions/workflows/test_s390x.yaml)
[![codecov](https://codecov.io/gh/emmansun/gmsm/branch/main/graph/badge.svg?token=Otdi8m8sFj)](https://codecov.io/gh/emmansun/gmsm)
[![Go Report Card](https://goreportcard.com/badge/github.com/emmansun/gmsm)](https://goreportcard.com/report/github.com/emmansun/gmsm)
[![Documentation](https://godoc.org/github.com/emmansun/gmsm?status.svg)](https://godoc.org/github.com/emmansun/gmsm)
![GitHub go.mod Go version (branch)](https://img.shields.io/github/go-mod/go-version/emmansun/gmsm)
[![Release](https://img.shields.io/github/release/emmansun/gmsm/all.svg)](https://github.com/emmansun/gmsm/releases)

[English](README-EN.md) | 简体中文

Go语言商用密码软件，简称**GMSM**，一个安全、高性能、易于使用的Go语言商用密码软件库，涵盖商用密码公开算法SM2/SM3/SM4/SM9/ZUC。

## 用户文档
- [SM2椭圆曲线公钥密码算法应用指南](./docs/sm2.md) 
- [SM3密码杂凑算法应用指南](./docs/sm3.md) 
- [SM4分组密码算法应用指南](./docs/sm4.md) 
- [SM9标识密码算法应用指南](./docs/sm9.md)
- [ZUC祖冲之序列密码算法应用指南](./docs/zuc.md)
- [CFCA互操作性指南](./docs/cfca.md)
- [PKCS7应用指南](./docs/pkcs7.md)
- [PKCS12应用指南](./docs/pkcs12.md)

如果你想提问题，建议你阅读[提问的智慧](https://github.com/ryanhanwu/How-To-Ask-Questions-The-Smart-Way/blob/main/README-zh_CN.md)。

## 核心模块

### 公钥密码算法

#### SM2 - 椭圆曲线公钥密码算法
SM2 椭圆曲线公钥密码算法的核心实现位于 [internal/sm2ec](https://github.com/emmansun/gmsm/tree/main/internal/sm2ec) 包中。本实现在性能上与 Go 标准库中 NIST P-256 曲线的原生实现（非 BoringCrypto）相当，并针对 **amd64**、**arm64**、**s390x**、**ppc64le**、**riscv64** 和 **loong64** 架构进行了汇编优化。

**功能特性：**
- 数字签名算法（GB/T 32918.2-2016）
- 公钥加密算法（GB/T 32918.4-2016）
- 密钥交换协议（GB/T 32918.3-2016）
- 密钥对保护数据格式（GB/T 35276-2017）

详细的性能优化分析和实现细节请参阅 [SM2 性能优化 Wiki](https://github.com/emmansun/gmsm/wiki/SM2%E6%80%A7%E8%83%BD%E4%BC%98%E5%8C%96)。

#### SM9 - 标识密码算法
SM9 标识密码算法的底层数学运算（素域、扩域、椭圆曲线及双线性对）实现于 [bn256](https://github.com/emmansun/gmsm/tree/main/sm9/bn256) 包中，支持 **amd64**、**arm64**、**ppc64x**、**riscv64** 和 **loong64** 架构的优化实现。

**功能特性：**
- 密钥生成算法（GM/T 0044-2016）
- 数字签名算法
- 密钥封装机制（KEM）
- 公钥加密算法
- 密钥交换协议

实现细节和优化策略请参阅 [SM9 实现及优化 Wiki](https://github.com/emmansun/gmsm/wiki/SM9%E5%AE%9E%E7%8E%B0%E5%8F%8A%E4%BC%98%E5%8C%96)。

---

### 对称密码算法

#### SM3 - 密码杂凑算法
SM3 密码杂凑算法（GM/T 0004-2012）实现了高效的 SIMD 优化：

**架构优化：**
- **amd64**：针对 AVX2+BMI2、AVX、SSE2+SSSE3 指令集优化消息扩展
- **arm64**：使用 NEON 指令优化消息扩展，并提供基于 A64 扩展密码指令的实现
- **s390x/ppc64x**：通过向量指令优化消息扩展

详细实现分析请参阅 [SM3 性能优化 Wiki](https://github.com/emmansun/gmsm/wiki/SM3%E6%80%A7%E8%83%BD%E4%BC%98%E5%8C%96)。

#### SM4 - 分组密码算法
SM4 分组密码算法（GM/T 0002-2012）实现了多架构汇编优化，并针对常用工作模式进行了融合优化：

**架构优化：**
- **amd64**：使用 AES-NI 指令结合 AVX2/AVX/SSE2+SSSE3
- **arm64**：使用 AES 指令结合 NEON，并提供基于 A64 扩展密码指令的实现
- **ppc64x**：使用 vsbox 指令结合向量指令

**工作模式优化：**
- ECB（电子密码本）
- CBC（密码块链接）
- GCM（伽罗瓦/计数器模式）
- XTS（可调整密文分组链接，支持 GB/T 17964-2021 和 NIST SP 800-38E）

详细实现分析请参阅 [SM4 性能优化 Wiki](https://github.com/emmansun/gmsm/wiki/SM4%E6%80%A7%E8%83%BD%E4%BC%98%E5%8C%96)。

#### ZUC - 祖冲之序列密码算法
祖冲之序列密码算法（GM/T 0001-2012）实现了基于 SIMD、AES 指令和无进位乘法指令的优化，支持 **amd64**、**arm64** 和 **ppc64x** 架构。

**功能特性：**
- 机密性算法（128-EEA3 / 256-EEA3）
- 完整性算法（128-EIA3 / 256-EIA3）

详细实现分析请参阅 [ZUC 实现及优化 Wiki](https://github.com/emmansun/gmsm/wiki/Efficient-Software-Implementations-of-ZUC)。

---

### 消息认证码

#### CBCMAC - 基于分组密码的消息认证码
符合《GB/T 15852.1-2020 信息安全技术 消息鉴别码算法 第1部分：采用分组密码的机制》标准，实现了多种 MAC 算法：

**支持的 MAC 模式：**
- CBC-MAC（方案 1）
- EMAC（方案 2）
- ANSI Retail MAC（方案 3）
- MAC-DES（方案 4）
- CMAC（方案 5，RFC 4493）
- LMAC（方案 6）
- TR-CBC-MAC（方案 7）
- CBCR-MAC（方案 8）

---

### 工作模式与填充

#### CIPHER - 分组密码工作模式
实现了《GB/T 17964-2021 信息安全技术 分组密码算法的工作模式》标准中定义的多种工作模式：

**支持的工作模式：**
- **ECB**：电子密码本模式
- **CCM**：计数器模式与 CBC-MAC 模式（RFC 3610）
- **XTS**：可调整密文分组链接模式（GB/T 17964-2021 / NIST SP 800-38E）
- **HCTR**：带泛杂凑函数的计数器模式（GB/T 17964-2021 新增）
- **BC**：分组链接模式（GB/T 17964 遗留模式）
- **OFBNLF**：带非线性函数的输出反馈模式（GB/T 17964 遗留模式）

**注意事项：**
- XTS 模式实现了 `cipher.BlockMode` 接口，内部包含 tweak 状态，**不支持并发使用**
- BC 模式与 CBC 模式功能相似
- OFBNLF 模式从软件实现角度性能优化空间有限

#### PADDING - 填充方案
实现了多种符合标准的填充方案，支持**常量时间去填充**防御 Padding Oracle 攻击：

| 填充方案 | 对应标准 |
|---------|---------|
| **PKCS#7** | GB/T 17964-2021 附录 C.2 填充方法 1 / RFC 5652 |
| **ISO/IEC 9797-1 方法 2** | GB/T 17964-2021 附录 C.3 填充方法 2 |
| **ANSI X.923** | ANSI X9.23 标准 |
| **ISO/IEC 9797-1 方法 3** | GB/T 17964-2021 附录 C.4 填充方法 3 |
| **Zero Padding** | 非标准（遗留兼容） |

**安全实现：**
- 所有方案提供 `ConstantTimeUnpad()` 和 `Unpad()` 两种方法
- 加密数据**必须**使用 `ConstantTimeUnpad()` 防御时序攻击
- `Unpad()` 仅用于非敏感数据的性能优化

---

### PKI 与证书

#### SMX509 - 国密证书扩展
基于 Go 标准库 `crypto/x509` 包扩展，增加了国密算法支持，实现符合《GM/T 0015-2012 基于 SM2 密码算法的数字证书格式规范》。

#### PKCS#7 - 加密消息语法
基于 [mozilla-services/pkcs7](https://github.com/mozilla-services/pkcs7) 项目（已于 2024 年 2 月归档）扩展，增加了国密算法支持，符合 RFC 2315 标准。

#### PKCS#8 - 私钥信息语法
基于 [youmark/pkcs8](https://github.com/youmark/pkcs8) 项目扩展，增加了国密算法支持，符合 RFC 5208 / RFC 5958 标准。

---

### 密钥协商与随机数

#### ECDH - 椭圆曲线 Diffie-Hellman
提供类似 Go 标准库 `crypto/ecdh` 的接口设计，支持 SM2 曲线的密钥协商协议：

**支持协议：**
- ECDH 密钥协商
- SM2MQV 密钥协商（推荐）

**特性：**
- 无 `big.Int` 依赖，性能更优
- 可作为 `sm2` 包密钥交换协议的替代实现

#### DRBG - 确定性随机位生成器
符合《GM/T 0105-2021 软件随机数发生器设计指南》标准，同时兼容 NIST SP 800-90A 部分要求。

**特性：**
- 使用 NIST 官方测试向量验证
- **不支持并发使用**

---

### CFCA 互操作性

#### CFCA - 中国金融认证中心扩展
提供与 CFCA SADK 的互操作性支持：

**功能特性：**
- SM2 私钥和证书封装（PKCS#12_SM2 格式）
- 信封加密与数字签名
- CSR 生成与解析
- 私钥解密

---

### 后量子密码学

#### MLKEM - 基于模格的密钥封装机制
符合 NIST FIPS 203 标准，基于 Go 标准库实现。

**支持参数集：**
- ML-KEM-512
- ML-KEM-768
- ML-KEM-1024

#### MLDSA - 基于模格的数字签名
符合 NIST FIPS 204 标准。

#### SLHDSA - 无状态哈希数字签名
符合 NIST FIPS 205 标准。

## 相关项目
- **[Trisia/TLCP](https://github.com/Trisia/gotlcp)** - 一个《GB/T 38636-2020 信息安全技术 传输层密码协议》Go语言实现项目。 
- **[Trisia/Randomness](https://github.com/Trisia/randomness)** - 一个Go语言随机性检测规范实现。
- **[PKCS12](https://github.com/emmansun/go-pkcs12)** - [SSLMate/go-pkcs12](https://github.com/SSLMate/go-pkcs12)项目的一个分支，加入了商用密码支持，由于PKCS12标准比较老，安全性不高，所以以独立项目进行维护。
- **[MKSMCERT](https://github.com/emmansun/mksmcert)** - 一个用于生成SM2私钥和证书的工具，主要用于开发测试，它是[FiloSottile/mkcert](https://github.com/FiloSottile/mkcert)项目的一个分支，加入了商用密码支持。
- **JavaScript实现**
  - [jsrsasign-sm](https://github.com/emmansun/sm2js) 扩展[jsrsasign](https://github.com/kjur/jsrsasign)实现的优势在于充分利用jsrsasign的PKIX，CSR，CERT，PKCS8等处理能力。
  - [sjcl-sm](https://github.com/emmansun/sm4js) 扩展[sjcl](https://github.com/bitwiseshiftleft/sjcl)实现的优势在于其丰富的对称加密模式实现，以及其简洁的代码、较好的性能。

## 软件许可
本软件使用MIT许可证，详情请参考[软件许可](./LICENSE)。如果不熟悉MIT许可证条款，请参考[MIT许可证](https://zh.wikipedia.org/zh-cn/MIT%E8%A8%B1%E5%8F%AF%E8%AD%89)。请知晓和遵守**被许可人义务**！

## 致谢
本项目的基础架构、设计和部分代码源自[golang crypto](https://github.com/golang/go/commits/master/src/crypto).

SM4分组密码算法**amd64** SIMD AES-NI实现（SSE部分）的算法源自[mjosaarinen/sm4ni](https://github.com/mjosaarinen/sm4ni)。

SM9/BN256最初版本的代码复制自[cloudflare/bn256](https://github.com/cloudflare/bn256)项目，后期对基础的素域、扩域、椭圆曲线运算等进行了重写。

祖冲之序列密码算法实现**amd64** SIMD AES-NI, CLMUL实现算法源自[Intel(R) Multi-Buffer Crypto for IPsec Library](https://github.com/intel/intel-ipsec-mb/)项目。

PKCS7包代码是[mozilla-services/pkcs7](https://github.com/mozilla-services/pkcs7)项目（该项目已于2024年2月10日被归档）的一个分支，加入了商用密码扩展。

PKCS8包代码是[youmark/pkcs8](https://github.com/youmark/pkcs8)项目的一个分支，加入了商用密码扩展。

## 免责声明

使用本项目前，请务必仔细阅读[GMSM软件免责声明](DISCLAIMER.md)！

## 支持与关注（⭐）
如果这个项目对你有帮助，欢迎点个 Star ⭐ 支持我们持续维护与优化。
[![Stargazers over time](https://starchart.cc/emmansun/gmsm.svg?variant=adaptive)](https://starchart.cc/emmansun/gmsm)
