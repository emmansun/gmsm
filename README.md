# Go语言商用密码软件

[![Github CI](https://github.com/emmansun/gmsm/actions/workflows/ci.yml/badge.svg)](https://github.com/emmansun/gmsm/actions/workflows/ci.yml)
[![arm64-qemu](https://github.com/emmansun/gmsm/actions/workflows/test_qemu.yml/badge.svg)](https://github.com/emmansun/gmsm/actions/workflows/test_qemu.yml)
[![sm3-sm4-ni-qemu](https://github.com/emmansun/gmsm/actions/workflows/test_sm_ni.yml/badge.svg)](https://github.com/emmansun/gmsm/actions/workflows/test_sm_ni.yml)
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

## 包结构
- **SM2** - SM2椭圆曲线公钥密码算法，曲线的具体实现位于[internal/sm2ec](https://github.com/emmansun/gmsm/tree/main/internal/sm2ec) package中。SM2曲线实现性能和Golang标准库中的NIST P256椭圆曲线原生实现（非BoringCrypto）类似，也对**amd64**，**arm64**，**s390x**和**ppc64le**架构做了专门汇编优化实现，您也可以参考[SM2实现细节](https://github.com/emmansun/gmsm/wiki/SM2%E6%80%A7%E8%83%BD%E4%BC%98%E5%8C%96)及相关Wiki和代码，以获得更多实现细节。SM2包实现了SM2椭圆曲线公钥密码算法的数字签名算法、公钥加密算法、密钥交换算法，以及《GB/T 35276-2017信息安全技术 SM2密码算法使用规范》中的密钥对保护数据格式。

- **SM3** - SM3密码杂凑算法实现。**amd64**下分别针对**AVX2+BMI2、AVX、SSE2+SSSE3**做了消息扩展部分的SIMD实现； **arm64**下使用NEON指令做了消息扩展部分的SIMD实现，同时也提供了基于**A64扩展密码指令**的汇编实现；**s390x**和**ppc64x**通过向量指令做了消息扩展部分的优化实现。您也可以参考[SM3性能优化](https://github.com/emmansun/gmsm/wiki/SM3%E6%80%A7%E8%83%BD%E4%BC%98%E5%8C%96)及相关Wiki和代码，以获得更多实现细节。

- **SM4** - SM4分组密码算法实现。**amd64**下使用**AES**指令加上**AVX2、AVX、SSE2+SSSE3**实现了比较好的性能。**arm64**下使用**AES**指令加上NEON指令实现了比较好的性能，同时也提供了基于**A64扩展密码指令**的汇编实现。**ppc64x**下使用**vsbox**指令加上向量指令进行了并行优化。针对**ECB/CBC/GCM/XTS**加密模式，做了和SM4分组密码算法的融合汇编优化实现。您也可以参考[SM4性能优化](https://github.com/emmansun/gmsm/wiki/SM4%E6%80%A7%E8%83%BD%E4%BC%98%E5%8C%96)及相关Wiki和代码，以获得更多实现细节。

- **SM9** - SM9标识密码算法实现。基础的素域、扩域、椭圆曲线运算以及双线性对运算位于[bn256](https://github.com/emmansun/gmsm/tree/main/sm9/bn256)包中，分别对**amd64**、**arm64**、**ppc64x**架构做了优化实现。您也可以参考[SM9实现及优化](https://github.com/emmansun/gmsm/wiki/SM9%E5%AE%9E%E7%8E%B0%E5%8F%8A%E4%BC%98%E5%8C%96)及相关讨论和代码，以获得更多实现细节。SM9包实现了SM9标识密码算法的密钥生成、数字签名算法、密钥封装机制和公钥加密算法、密钥交换协议。

- **ZUC** - 祖冲之序列密码算法实现。使用SIMD、AES指令以及无进位乘法指令，分别对**amd64**、**arm64**和**ppc64x**架构做了优化实现, 您也可以参考[ZUC实现及优化](https://github.com/emmansun/gmsm/wiki/Efficient-Software-Implementations-of-ZUC)和相关代码，以获得更多实现细节。ZUC包实现了基于祖冲之序列密码算法的机密性算法、128/256位完整性算法。

- **CBCMAC** - 符合《GB/T 15852.1-2020 采用分组密码的机制》的消息鉴别码。 
- **CFCA** - CFCA（中金）特定实现，目前实现的是SM2私钥、证书封装处理，对应SADK中的**PKCS12_SM2**；信封加密、签名；CSR生成及返回私钥解密、解析等功能。

- **CIPHER** - ECB/CCM/XTS/HCTR/BC/OFBNLF加密模式实现。XTS模式同时支持NIST规范和国标 **GB/T 17964-2021**。当前的XTS模式由于实现了BlockMode，其结构包含一个tweak数组，所以其**不支持并发使用**。**分组链接（BC）模式**和**带非线性函数的输出反馈（OFBNLF）模式**为分组密码算法的工作模式标准**GB/T 17964**的遗留模式，**带泛杂凑函数的计数器（HCTR）模式**是**GB/T 17964-2021**中的新增模式。分组链接（BC）模式和CBC模式类似；而带非线性函数的输出反馈（OFBNLF）模式的话，从软件实现的角度来看，基本没有性能优化的空间。

- **SMX509** - Go语言X509包的分支，加入了商用密码支持。

- **PADDING** - 一些填充方法实现（非常量时间运行）：**pkcs7**，这是当前主要使用的填充方式，对应**GB/T 17964-2021**的附录C.2 填充方法 1；**iso9797m2**，对应**GB/T 17964-2021**的附录C.3 填充方法 2；**ansix923**，对应ANSI X9.23标准。**GB/T 17964-2021**的附录C.4 填充方法 3，对应ISO/IEC_9797-1 padding method 3。

- **PKCS7** - [mozilla-services/pkcs7](https://github.com/mozilla-services/pkcs7) 项目（该项目已于2024年2月10日被归档）的分支，加入了商用密码支持。

- **PKCS8** - [youmark/pkcs8](https://github.com/youmark/pkcs8)项目的分支，加入了商用密码支持。

- **ECDH** - 一个类似Go语言中ECDH包的实现，支持SM2椭圆曲线密码算法的ECDH & SM2MQV协议，该实现没有使用 **big.Int**，也是一个SM2包中密钥交换协议实现的替换实现（推荐使用）。

- **DRBG** - 《GM/T 0105-2021软件随机数发生器设计指南》实现。本实现同时支持**NIST Special Publication 800-90A**（部分） 和 **GM/T 0105-2021**，NIST相关实现使用了NIST提供的测试数据进行测试。本实现**不支持并发使用**。

- **MLDSA** - NIST FIPS 204 Module-Lattice-Based Digital Signature Standard实现。

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

## 项目星标趋势
[![Stargazers over time](https://starchart.cc/emmansun/gmsm.svg?variant=adaptive)](https://starchart.cc/emmansun/gmsm)
