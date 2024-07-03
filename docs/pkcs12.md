# [go-pkcs12](https://github.com/emmansun/go-pkcs12)应用指南
[PKCS #12: Personal Information Exchange Syntax v1.1](https://datatracker.ietf.org/doc/html/rfc7292)，PKCS12目前似乎没有相应的国密标准。
定制PKCS12的目的是：
1. 可以处理**SM2**私钥和证书。
2. 可以替代、使用一些商密算法，主要是**SM3**和**SM4**。

## PKCS#12的解析
[go-pkcs12](https://github.com/emmansun/go-pkcs12)提供三个方法：

| 方法 | 适用 | 具体说明 |  
| :--- | :--- | :--- |  
| ```DecodeChain``` | 抽取出一个私钥、一个相应证书以及证书链 | 私钥和相应证书必须存在，否则报错 |  
| ```Decode``` | 抽取出一个私钥、一个相应证书 | 私钥和相应证书必须存在，否则报错；并且**不能有证书链存在**。 |  
| ```DecodeTrustStore``` | 抽取出证书链 | 只支持java的TrustStore, [Difference Between a Java Keystore and a Truststore](https://www.baeldung.com/java-keystore-truststore-difference) |  

### 解码能处理的算法

#### 证书及私钥加密算法
这里主要是**PBES(Password-Based Encryption Scheme)**, 它主要涉及几方面：  
1. 密码处理  
2. 从密码派生出加密密钥
3. 具体对称加密算法

**PBES-PKCS12**
* pbeWithSHAAnd3-KeyTripleDES-CBC OBJECT IDENTIFIER ::= {pkcs-12PbeIds 3}
* pbeWithSHAAnd128BitRC2-CBC      OBJECT IDENTIFIER ::= {pkcs-12PbeIds 5}
* pbewithSHAAnd40BitRC2-CBC       OBJECT IDENTIFIER ::= {pkcs-12PbeIds 6}  

不同于**PKCS#5 v1.5**中的**PBES1**，上述这些是**PKCS#12**的独有算法，特别是它的**KDF**和**密码处理**。

**PBES1**  
PBES1属于老旧遗留算法，目前版本未实现。

**PBES2**  
由两部分组成，分别为**KDF**和加密算法。目前KDF只支持**KDF2**, KDF2中支持的**PRF**方法有：
* id-hmacWithSHA1
* id-hmacWithSHA256
* id-hmacWithSM3

具体可参考[PKCS #5: Password-Based Cryptography Specification Version 2.1](https://datatracker.ietf.org/doc/html/rfc8018)

加密算法有：  
* AES-CBC-Pad，密钥长度支持16/24/32字节
* SM4-CBC-Pad，密钥长度支持16字节

#### 数据完整性保护
这里只支持基于密码的完整性保护：**HMAC**。支持的HASH算法有：
* SHA1
* SHA256
* SM3

## PKCS#12的生成
目前只支持下列几种，不支持自由定义：

* ```LegacyRC2```，加密使用PKCS12特有算法；对证书使用RC2加密，对私钥使用3DES加密，一致性保证使用HMAC-SHA1。
* ```LegacyDES```，加密使用PKCS12特有算法；对证书和私钥都是用3DES加密，一致性保证使用HMAC-SHA1。
* ```Passwordless```，无加密、一致性保证模式。
* ```Modern2023```，对应OpenSSL 3+ 默认，加密使用AES-256-CBC with PBKDF2，一致性保证使用HMAC-SHA256。
* ```ShangMi2024```，这个估计目前没什么互操作性。

目前的全局函数```Encode``` / ```EncodeTrustStore```使用**LegacyRC2**编码器。

```go
// LegacyRC2 encodes PKCS#12 files using weak algorithms that were
// traditionally used in PKCS#12 files, including those produced
// by OpenSSL before 3.0.0, go-pkcs12 before 0.3.0, and Java when
// keystore.pkcs12.legacy is defined.  Specifically, certificates
// are encrypted using PBE with RC2, and keys are encrypted using PBE
// with 3DES, using keys derived with 2048 iterations of HMAC-SHA-1.
// MACs use HMAC-SHA-1 with keys derived with 1 iteration of HMAC-SHA-1.
//
// Due to the weak encryption, it is STRONGLY RECOMMENDED that you use [DefaultPassword]
// when encoding PKCS#12 files using this encoder, and protect the PKCS#12 files
// using other means.
//
// By default, OpenSSL 3 can't decode PKCS#12 files created using this encoder.
// For better compatibility, use [LegacyDES].  For better security, use
// [Modern2023].
var LegacyRC2 = &Encoder{
	macAlgorithm:         oidSHA1,
	certAlgorithm:        oidPBEWithSHAAnd40BitRC2CBC,
	keyAlgorithm:         oidPBEWithSHAAnd3KeyTripleDESCBC,
	kdfPrf:               nil,
	encryptionScheme:     nil,
	macIterations:        1,
	encryptionIterations: 2048,
	saltLen:              8,
	rand:                 rand.Reader,
}

// LegacyDES encodes PKCS#12 files using weak algorithms that are
// supported by a wide variety of software.  Certificates and keys
// are encrypted using PBE with 3DES using keys derived with 2048
// iterations of HMAC-SHA-1.  MACs use HMAC-SHA-1 with keys derived
// with 1 iteration of HMAC-SHA-1.  These are the same parameters
// used by OpenSSL's -descert option.  As of 2023, this encoder is
// likely to produce files that can be read by the most software.
//
// Due to the weak encryption, it is STRONGLY RECOMMENDED that you use [DefaultPassword]
// when encoding PKCS#12 files using this encoder, and protect the PKCS#12 files
// using other means.  To create more secure PKCS#12 files, use [Modern2023].
var LegacyDES = &Encoder{
	macAlgorithm:         oidSHA1,
	certAlgorithm:        oidPBEWithSHAAnd3KeyTripleDESCBC,
	keyAlgorithm:         oidPBEWithSHAAnd3KeyTripleDESCBC,
	kdfPrf:               nil,
	encryptionScheme:     nil,
	macIterations:        1,
	encryptionIterations: 2048,
	saltLen:              8,
	rand:                 rand.Reader,
}

// Passwordless encodes PKCS#12 files without any encryption or MACs.
// A lot of software has trouble reading such files, so it's probably only
// useful for creating Java trust stores using [Encoder.EncodeTrustStore]
// or [Encoder.EncodeTrustStoreEntries].
//
// When using this encoder, you MUST specify an empty password.
var Passwordless = &Encoder{
	macAlgorithm:     nil,
	certAlgorithm:    nil,
	keyAlgorithm:     nil,
	kdfPrf:           nil,
	encryptionScheme: nil,
	rand:             rand.Reader,
}

// Modern2023 encodes PKCS#12 files using algorithms that are considered modern
// as of 2023.  Private keys and certificates are encrypted using PBES2 with
// PBKDF2-HMAC-SHA-256 and AES-256-CBC.  The MAC algorithm is HMAC-SHA-2.  These
// are the same algorithms used by OpenSSL 3 (by default), Java 20 (by default),
// and Windows Server 2019 (when "stronger" is used).
//
// Files produced with this encoder can be read by OpenSSL 1.1.1 and higher,
// Java 12 and higher, and Windows Server 2019 and higher.
//
// For passwords, it is RECOMMENDED that you do one of the following:
// 1) Use [DefaultPassword] and protect the file using other means, or
// 2) Use a high-entropy password, such as one generated with `openssl rand -hex 16`.
//
// You SHOULD NOT use a lower-entropy password with this encoder because the number of KDF
// iterations is only 2048 and doesn't provide meaningful protection against
// brute-forcing.  You can increase the number of iterations using [Encoder.WithIterations],
// but as https://neilmadden.blog/2023/01/09/on-pbkdf2-iterations/ explains, this doesn't
// help as much as you think.
var Modern2023 = &Encoder{
	macAlgorithm:         oidSHA256,
	certAlgorithm:        oidPBES2,
	keyAlgorithm:         oidPBES2,
	kdfPrf:               oidHmacWithSHA256,
	encryptionScheme:     oidAES256CBC,	
	macIterations:        2048,
	encryptionIterations: 2048,
	saltLen:              16,
	rand:                 rand.Reader,
}

// ShangMi2024 encodes PKCS#12 files using algorithms that are all ShangMi.
// Private keys and certificates are encrypted using PBES2 with	 PBKDF2-HMAC-SM3 and SM4-CBC.
// The MAC algorithm is HMAC-SM3. 
var ShangMi2024 = &Encoder{
	macAlgorithm:         oidSM3,
	certAlgorithm:        oidPBES2,
	keyAlgorithm:         oidPBES2,
	kdfPrf:               oidHmacWithSM3,
	encryptionScheme:     oidSM4CBC,
	macIterations:        2048,
	encryptionIterations: 2048,
	saltLen:              16,
	rand:                 rand.Reader,
}
```
