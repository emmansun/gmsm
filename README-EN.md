# Go ShangMi (Commercial Cryptography) Library

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

English | [简体中文](README.md)

Go ShangMi (Commercial Cryptography) Library, abbreviated as **GMSM**, is a secure, high-performance, and easy-to-use Go cryptographic library that covers the Chinese commercial cryptographic public algorithms SM2/SM3/SM4/SM9/ZUC.

## User Documentation
- [SM2 Elliptic Curve Public Key Cryptography Algorithm Application Guide](./docs/sm2-en.md)
- [SM3 Cryptographic Hash Algorithm Application Guide](./docs/sm3.md)
- [SM4 Block Cipher Algorithm Application Guide](./docs/sm4.md)
- [SM9 Identity-Based Cryptography Algorithm Application Guide](./docs/sm9.md)
- [ZUC Stream Cipher Algorithm Application Guide](./docs/zuc.md)
- [CFCA Interoperability Guide](./docs/cfca.md)
- [PKCS#7 Application Guide](./docs/pkcs7.md)
- [PKCS#12 Application Guide](./docs/pkcs12.md)

If you want to raise an issue, we recommend reading [How To Ask Questions The Smart Way](https://github.com/ryanhanwu/How-To-Ask-Questions-The-Smart-Way).

## Core Modules

### Public Key Cryptography Algorithms

#### SM2 - Elliptic Curve Public Key Cryptography Algorithm
The core implementation of SM2 elliptic curve public key cryptography algorithm is located in the [internal/sm2ec](https://github.com/emmansun/gmsm/tree/main/internal/sm2ec) package. This implementation achieves performance comparable to the native NIST P-256 curve implementation in the Go standard library (non-BoringCrypto) and includes assembly optimizations for **amd64**, **arm64**, **s390x**, **ppc64le**, **riscv64**, and **loong64** architectures.

**Features:**
- Digital Signature Algorithm (GB/T 32918.2-2016)
- Public Key Encryption Algorithm (GB/T 32918.4-2016)
- Key Exchange Protocol (GB/T 32918.3-2016)
- Key Pair Protection Data Format (GB/T 35276-2017)

For detailed performance optimization analysis and implementation details, please refer to the [SM2 Performance Optimization Wiki](https://github.com/emmansun/gmsm/wiki/SM2%E6%80%A7%E8%83%BD%E4%BC%98%E5%8C%96).

#### SM9 - Identity-Based Cryptography Algorithm
The underlying mathematical operations (prime fields, extension fields, elliptic curves, and bilinear pairings) of SM9 identity-based cryptography algorithm are implemented in the [bn256](https://github.com/emmansun/gmsm/tree/main/sm9/bn256) package, with optimizations for **amd64**, **arm64**, **ppc64x**, **riscv64**, and **loong64** architectures.

**Features:**
- Key Generation Algorithm (GM/T 0044-2016)
- Digital Signature Algorithm
- Key Encapsulation Mechanism (KEM)
- Public Key Encryption Algorithm
- Key Exchange Protocol

For implementation details and optimization strategies, please refer to the [SM9 Implementation and Optimization Wiki](https://github.com/emmansun/gmsm/wiki/SM9%E5%AE%9E%E7%8E%B0%E5%8F%8A%E4%BC%98%E5%8C%96).

---

### Symmetric Cryptography Algorithms

#### SM3 - Cryptographic Hash Algorithm
SM3 cryptographic hash algorithm (GM/T 0004-2012) implements efficient SIMD optimizations:

**Architecture Optimizations:**
- **amd64**: Optimizes message expansion for AVX2+BMI2, AVX, and SSE2+SSSE3 instruction sets
- **arm64**: Uses NEON instructions to optimize message expansion and provides implementation based on A64 extended cryptographic instructions
- **s390x/ppc64x**: Optimizes message expansion through vector instructions

For detailed implementation analysis, please refer to the [SM3 Performance Optimization Wiki](https://github.com/emmansun/gmsm/wiki/SM3%E6%80%A7%E8%83%BD%E4%BC%98%E5%8C%96).

#### SM4 - Block Cipher Algorithm
SM4 block cipher algorithm (GM/T 0002-2012) implements multi-architecture assembly optimizations with fused optimizations for common operation modes:

**Architecture Optimizations:**
- **amd64**: Uses AES-NI instructions combined with AVX2/AVX/SSE2+SSSE3
- **arm64**: Uses AES instructions combined with NEON and provides implementation based on A64 extended cryptographic instructions
- **ppc64x**: Uses vsbox instructions combined with vector instructions

**Operation Mode Optimizations:**
- ECB (Electronic Codebook)
- CBC (Cipher Block Chaining)
- GCM (Galois/Counter Mode)
- XTS (XEX-based tweaked-codebook mode, supports GB/T 17964-2021 and NIST SP 800-38E)

For detailed implementation analysis, please refer to the [SM4 Performance Optimization Wiki](https://github.com/emmansun/gmsm/wiki/SM4%E6%80%A7%E8%83%BD%E4%BC%98%E5%8C%96).

#### ZUC - Zu Chongzhi Stream Cipher Algorithm
The Zu Chongzhi stream cipher algorithm (GM/T 0001-2012) implements optimizations based on SIMD, AES instructions, and carry-less multiplication instructions, supporting **amd64**, **arm64**, and **ppc64x** architectures.

**Features:**
- Confidentiality Algorithm (128-EEA3 / 256-EEA3)
- Integrity Algorithm (128-EIA3 / 256-EIA3)

For detailed implementation analysis, please refer to the [Efficient Software Implementations of ZUC Wiki](https://github.com/emmansun/gmsm/wiki/Efficient-Software-Implementations-of-ZUC).

---

### Message Authentication Codes

#### CBCMAC - Block Cipher Based Message Authentication Code
Compliant with the standard "GB/T 15852.1-2020 Information Security Technology - Message Authentication Code Algorithm Part 1: Mechanism using a Block Cipher", implementing various MAC algorithms:

**Supported MAC Modes:**
- CBC-MAC (Scheme 1)
- EMAC (Scheme 2)
- ANSI Retail MAC (Scheme 3)
- MAC-DES (Scheme 4)
- CMAC (Scheme 5, RFC 4493)
- LMAC (Scheme 6)
- TR-CBC-MAC (Scheme 7)
- CBCR-MAC (Scheme 8)

---

### Operation Modes and Padding

#### CIPHER - Block Cipher Operation Modes
Implements various operation modes defined in the standard "GB/T 17964-2021 Information Security Technology - Modes of Operation for Block Ciphers":

**Supported Operation Modes:**
- **ECB**: Electronic Codebook mode
- **CCM**: Counter with CBC-MAC mode (RFC 3610)
- **XTS**: XEX-based tweaked-codebook mode (GB/T 17964-2021 / NIST SP 800-38E)
- **HCTR**: Hash-Counter mode (newly added in GB/T 17964-2021)
- **BC**: Block Chaining mode (GB/T 17964 legacy mode)
- **OFBNLF**: Output Feedback mode with Non-Linear Function (GB/T 17964 legacy mode)

**Notes:**
- XTS mode implements the `cipher.BlockMode` interface and contains internal tweak state, **does NOT support concurrent use**
- BC mode has similar functionality to CBC mode
- OFBNLF mode has limited room for performance optimization from a software implementation perspective

#### PADDING - Padding Schemes
Implements various standards-compliant padding schemes with **constant-time unpadding** to defend against Padding Oracle attacks:

| Padding Scheme | Corresponding Standard |
|---------------|------------------------|
| **PKCS#7** | GB/T 17964-2021 Appendix C.2 Padding Method 1 / RFC 5652 |
| **ISO/IEC 9797-1 Method 2** | GB/T 17964-2021 Appendix C.3 Padding Method 2 |
| **ANSI X.923** | ANSI X9.23 Standard |
| **ISO/IEC 9797-1 Method 3** | GB/T 17964-2021 Appendix C.4 Padding Method 3 |
| **Zero Padding** | Non-standard (legacy compatibility) |

**Secure Implementation:**
- All schemes provide both `ConstantTimeUnpad()` and `Unpad()` methods
- Encrypted data **MUST** use `ConstantTimeUnpad()` to defend against timing attacks
- `Unpad()` is only for performance optimization with non-sensitive data

---

### PKI and Certificates

#### SMX509 - Chinese Commercial Cryptography Certificate Extension
Extended from the Go standard library `crypto/x509` package with added support for Chinese commercial cryptography algorithms, compliant with "GM/T 0015-2012 Digital Certificate Format Specification Based on SM2 Cryptographic Algorithm".

#### PKCS#7 - Cryptographic Message Syntax
Extended from the [mozilla-services/pkcs7](https://github.com/mozilla-services/pkcs7) project (archived in February 2024) with added support for Chinese commercial cryptography algorithms, compliant with RFC 2315 standard.

#### PKCS#8 - Private-Key Information Syntax
Extended from the [youmark/pkcs8](https://github.com/youmark/pkcs8) project with added support for Chinese commercial cryptography algorithms, compliant with RFC 5208 / RFC 5958 standards.

---

### Key Agreement and Random Numbers

#### ECDH - Elliptic Curve Diffie-Hellman
Provides an interface design similar to the Go standard library `crypto/ecdh`, supporting SM2 curve key agreement protocols:

**Supported Protocols:**
- ECDH Key Agreement
- SM2MQV Key Agreement (recommended)

**Features:**
- No `big.Int` dependency for better performance
- Can serve as an alternative implementation to the `sm2` package key exchange protocol

#### DRBG - Deterministic Random Bit Generator
Compliant with "GM/T 0105-2021 Software Random Number Generator Design Guide" and compatible with NIST SP 800-90A partial requirements.

**Features:**
- Validated with NIST official test vectors
- **Does NOT support concurrent use**

---

### CFCA Interoperability

#### CFCA - China Financial Certification Authority Extension
Provides interoperability support with CFCA SADK:

**Features:**
- SM2 private key and certificate encapsulation (PKCS#12_SM2 format)
- Envelope encryption and digital signature
- CSR generation and parsing
- Private key decryption

---

### Post-Quantum Cryptography

#### MLKEM - Module-Lattice-Based Key-Encapsulation Mechanism
Compliant with NIST FIPS 203 standard, based on the Go standard library implementation.

**Supported Parameter Sets:**
- ML-KEM-512
- ML-KEM-768
- ML-KEM-1024

#### MLDSA - Module-Lattice-Based Digital Signature
Compliant with NIST FIPS 204 standard.

#### SLHDSA - Stateless Hash-Based Digital Signature
Compliant with NIST FIPS 205 standard.

## Related Projects
- **[Trisia/TLCP](https://github.com/Trisia/gotlcp)** - A Go language implementation of "GB/T 38636-2020 Information Security Technology - Transport Layer Cryptography Protocol".
- **[Trisia/Randomness](https://github.com/Trisia/randomness)** - A Go language implementation of randomness testing specifications.
- **[PKCS12](https://github.com/emmansun/go-pkcs12)** - A fork of [SSLMate/go-pkcs12](https://github.com/SSLMate/go-pkcs12) with commercial cryptography support. Due to the older PKCS12 standard and lower security, it is maintained as a separate project.
- **[MKSMCERT](https://github.com/emmansun/mksmcert)** - A tool for generating SM2 private keys and certificates, mainly for development and testing. It is a fork of [FiloSottile/mkcert](https://github.com/FiloSottile/mkcert) with commercial cryptography support.
- **JavaScript Implementations**
  - [jsrsasign-sm](https://github.com/emmansun/sm2js) - Extended implementation of [jsrsasign](https://github.com/kjur/jsrsasign) that takes full advantage of jsrsasign's PKIX, CSR, CERT, PKCS8, and other processing capabilities.
  - [sjcl-sm](https://github.com/emmansun/sm4js) - Extended implementation of [sjcl](https://github.com/bitwiseshiftleft/sjcl) that leverages its rich symmetric encryption mode implementation, concise code, and good performance.

## License
This software is licensed under the MIT License. For details, please refer to the [LICENSE](./LICENSE) file. If you are unfamiliar with the terms of the MIT License, please refer to [MIT License](https://en.wikipedia.org/wiki/MIT_License). Please be aware of and comply with the **licensee obligations**!

## Acknowledgements
The basic architecture, design, and some code of this project are derived from [golang crypto](https://github.com/golang/go/commits/master/src/crypto).

The SM4 block cipher algorithm **amd64** SIMD AES-NI implementation (SSE part) algorithm is derived from [mjosaarinen/sm4ni](https://github.com/mjosaarinen/sm4ni).

The initial version of SM9/BN256 code was copied from the [cloudflare/bn256](https://github.com/cloudflare/bn256) project, and later the basic prime field, extension field, elliptic curve operations, etc. were rewritten.

The Zu Chongzhi stream cipher algorithm implementation **amd64** SIMD AES-NI, CLMUL implementation algorithm is derived from the [Intel(R) Multi-Buffer Crypto for IPsec Library](https://github.com/intel/intel-ipsec-mb/) project.

The PKCS7 package code is a fork of the [mozilla-services/pkcs7](https://github.com/mozilla-services/pkcs7) project (which was archived on February 10, 2024) with commercial cryptography extensions.

The PKCS8 package code is a fork of the [youmark/pkcs8](https://github.com/youmark/pkcs8) project with commercial cryptography extensions.

## Disclaimer

Before using this project, please be sure to carefully read the [GMSM Software Disclaimer](DISCLAIMER.md)!

## Stargazers Over Time
[![Stargazers over time](https://starchart.cc/emmansun/gmsm.svg?variant=adaptive)](https://starchart.cc/emmansun/gmsm)