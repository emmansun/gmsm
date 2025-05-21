
# GM-Standards SM2/SM3/SM4/SM9/ZUC for Go

[![Github CI](https://github.com/emmansun/gmsm/actions/workflows/ci.yml/badge.svg)](https://github.com/emmansun/gmsm/actions/workflows/ci.yml)
[![arm64-qemu](https://github.com/emmansun/gmsm/actions/workflows/test_qemu.yml/badge.svg)](https://github.com/emmansun/gmsm/actions/workflows/test_qemu.yml)
[![sm3-sm4-ni-qemu](https://github.com/emmansun/gmsm/actions/workflows/test_sm_ni.yml/badge.svg)](https://github.com/emmansun/gmsm/actions/workflows/test_sm_ni.yml)
[![codecov](https://codecov.io/gh/emmansun/gmsm/branch/main/graph/badge.svg?token=Otdi8m8sFj)](https://codecov.io/gh/emmansun/gmsm)
[![Go Report Card](https://goreportcard.com/badge/github.com/emmansun/gmsm)](https://goreportcard.com/report/github.com/emmansun/gmsm)
[![Documentation](https://godoc.org/github.com/emmansun/gmsm?status.svg)](https://godoc.org/github.com/emmansun/gmsm)
![GitHub go.mod Go version (branch)](https://img.shields.io/github/go-mod/go-version/emmansun/gmsm)
[![Release](https://img.shields.io/github/release/emmansun/gmsm/all.svg)](https://github.com/emmansun/gmsm/releases)

English | [简体中文](README.md)

ShangMi (SM) cipher suites for Golang, referred to as **GMSM**, is a secure, high-performance, easy-to-use Golang ShangMi (SM) cipher suites library, covering public algorithms SM2/SM3/SM4/SM9/ZUC.

## Packages
- **SM2** - This is a SM2 sm2p256v1 implementation whose performance is similar like golang native NIST P256 under **amd64**, **arm64**, **s390x** and **ppc64le**, for implementation detail, please refer [SM2实现细节](https://github.com/emmansun/gmsm/wiki/SM2%E6%80%A7%E8%83%BD%E4%BC%98%E5%8C%96). It supports ShangMi sm2 digital signature, public key encryption algorithm and also key exchange.

- **SM3** - This is also a SM3 implementation whose performance is similar like golang native SHA 256 with SIMD under **amd64**, **arm64**, **s390x**, **ppc64x**, for implementation detail, please refer [SM3性能优化](https://github.com/emmansun/gmsm/wiki/SM3%E6%80%A7%E8%83%BD%E4%BC%98%E5%8C%96). It also provides A64 cryptographic instructions SM3 tested with QEMU.

- **SM4** - For SM4 implementation, SIMD & AES-NI are used under **amd64**, **arm64** and **ppc64x**, for detail please refer [SM4性能优化](https://github.com/emmansun/gmsm/wiki/SM4%E6%80%A7%E8%83%BD%E4%BC%98%E5%8C%96). It is optimized for **ECB/CBC/GCM/XTS** operation modes. It also provides A64 cryptographic instructions SM4 tested with QEMU.

- **SM9** - For SM9 implementation, please reference [SM9实现及优化](https://github.com/emmansun/gmsm/wiki/SM9%E5%AE%9E%E7%8E%B0%E5%8F%8A%E4%BC%98%E5%8C%96)

- **ZUC** - For ZUC implementation, SIMD, AES-NI and CLMUL are used under **amd64**, **arm64** and **ppc64x**, for detail please refer [Efficient Software Implementations of ZUC](https://github.com/emmansun/gmsm/wiki/Efficient-Software-Implementations-of-ZUC)

- **CBCMAC** - CBC-MAC and its variants (EMAC/ANSI retail MAC/MacDES/CMAC/LMAC/TrCBC/CBCR).
- **CFCA** - some cfca specific implementations.

- **CIPHER** - ECB/CCM/XTS/HCTR/BC/OFBNLF operation modes, XTS mode also supports **GB/T 17964-2021**. Current XTS mode implementation is **NOT** concurrent safe! **BC** and **OFBNLF** are legacy operation modes, **HCTR** is new operation mode in **GB/T 17964-2021**. **BC** operation mode is similar like **CBC**, there is no room for performance optimization in **OFBNLF** operation mode.

- **SMX509** - a fork of golang X509 that supports ShangMi.

- **PKCS7** - a fork of [mozilla-services/pkcs7](https://github.com/mozilla-services/pkcs7) that supports ShangMi.

- **PKCS8** - a fork of [youmark/pkcs8](https://github.com/youmark/pkcs8) that supports ShangMi.

- **ECDH** - a similar implementation of golang ECDH that supports SM2 ECDH & SM2MQV without usage of **big.Int**, a replacement of SM2 key exchange. For detail, pleaes refer [is my code constant time?](https://github.com/emmansun/gmsm/wiki/is-my-code-constant-time%3F)

- **DRBG** - Random Number Generation Using Deterministic Random Bit Generators, for detail, please reference **NIST Special Publication 800-90A** and **GM/T 0105-2021**: CTR-DRBG using derivation function and HASH-DRBG. NIST related implementations are tested with part of NIST provided test vectors. It's **NOT** concurrent safe! You can also use [randomness](https://github.com/Trisia/randomness) tool to check the generated random bits.

- **MLDSA** - NIST FIPS 204 Module-Lattice-Based Digital Signature Standard.

- **SLHDSA** - NIST FIPS 205 Stateless Hash-Based Digital Signature Standard

## Some Related Projects
- **[TLCP](https://github.com/Trisia/gotlcp)** - An implementation of **GB/T 38636-2020 Information security technology Transport Layer Cryptography Protocol (TLCP)**. 
- **[Trisia/Randomness](https://github.com/Trisia/randomness)** - An implementation of **GM/T 0005-2021 Randomness test specification**.
- **[PKCS12](https://github.com/emmansun/go-pkcs12)** - pkcs12 supports ShangMi, a fork of [SSLMate/go-pkcs12](https://github.com/SSLMate/go-pkcs12).
- **[MKSMCERT](https://github.com/emmansun/mksmcert)** - A simple tool for making locally-trusted development ShangMi certificates, a fork of [FiloSottile/mkcert](https://github.com/FiloSottile/mkcert).

## License
This work is licensed under a MIT License. See the [LICENSE](./LICENSE) file for details.

## Acknowledgements
The basic architecture, design and some codes are from [golang crypto](https://github.com/golang/go/commits/master/src/crypto).

The SM4 amd64 SIMD AES-NI implementation is inspired by code from [mjosaarinen/sm4ni](https://github.com/mjosaarinen/sm4ni). 

The original SM9/BN256 version is based on code from [cloudflare/bn256](https://github.com/cloudflare/bn256).

The ZUC amd64 SIMD AES-NI, CLMUL implementation is inspired by code from [Intel(R) Multi-Buffer Crypto for IPsec Library](https://github.com/intel/intel-ipsec-mb/).

The pkcs7 is based on code from [mozilla-services/pkcs7](https://github.com/mozilla-services/pkcs7), which has been archived by the owner on Feb 10, 2024.

The pkcs8 is based on code from [youmark/pkcs8](https://github.com/youmark/pkcs8).

## Disclaimer
This library is not fully audited and is offered as-is, and without a guarantee. Therefore, it is expected that changes in the code, repository, and API occur in the future. We recommend to take caution before using this library in a production application.

## Stargazers over time
[![Stargazers over time](https://starchart.cc/emmansun/gmsm.svg?variant=adaptive)](https://starchart.cc/emmansun/gmsm)
