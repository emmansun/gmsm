# CFCA互操作性指南
这是一份**不完整**的CFCA互操作性指南。

## 什么是CFCA
CFCA是中国金融认证中心的英文缩写。

## 什么是SADK
SADK（Security Application Development Kit）是CFCA推出的一套支持全平台、全浏览器、多语言的安全应用开发套件。实现了证书下载、证书应用过程中的全业务功能覆盖，可与客户业务系统、CFCA RA、CA、统一下载平台无缝对接，为用户提供证书下载、证书更新、签名验签、加密解密等全方位的数字证书安全服务。具体说明请参考[数字证书安全应用开发套件SADK](https://www.cfca.com.cn/20150807/101228565.html)。

其JAVA版本(其它语言版本未知)基本上是一个基于[Bouncy Castle](https://www.bouncycastle.org/)的实现（当然它看起来也支持JNI接入OpenSSL、U盾？）。

## 为什么会有互操作性问题
* CFCA有一些实现没有相关标准。
* SADK存在较早，可能有些实现早于标准发布。
* SADK版本较多，不同版本也会有互操作性兼容问题。
* 其它未知原因。

因为我也找不到SADK的版本历史或者Change Log，这里只是根据有限资料的一些判断。

## 容易出现互操作性问题的功能
相对而言，互操作性问题主要出现在SM2椭圆曲线公钥密码算法应用上，特别是加解密、数字信封加解密上。

### SM2加解密
加解密算法实现部分没有什么互操作性问题，主要是密文格式问题。

#### SADK 3.2之前版本
由于没有版本历史，所以这里只是大致推测（如果有不准确之处，敬请指出）。  
SADK 3.2之前的版本，只支持C1C2C3密文格式，而且C1只支持非压缩点格式，且输出忽略0x04这个点非压缩标识。  

| 随机点 | 密文 | SM3哈希值 |  
| :--- | :--- | :--- |  
| C1 (64 bytes) | C2 | C3 (32 bytes) |  

所以如果和SADK 3.2之前的应用交互，加密输出格式只能选C1C2C3，且密文通过切片操作忽略首字节（0x04这个点非压缩标识）；反之，如果是解密SADK 3.2之前的应用提供的密文，则要指定C1C2C3格式，同时，自己在密文前添加0x04这个点非压缩标识。**互操作的重要前提是知道对方的密文格式**。

#### SADK 3.2+版本
SADK 3.2之后的版本，支持下列SM2密文格式(encryptedType)：

| encryptedType | 输出格式 | 用本软件库如何解密 |   
| :--- | :--- | :--- |  
| 0 | ASN.1编码格式 `EncryptUtil.encrypt` 方法默认 | 正常解密 |
| 2 | C1C3C2 格式，带0x04这个点非压缩标识 | 正常解密 |
| 4 | C1C3C2 格式，不带0x04这个点非压缩标识 （`EncryptUtil.encryptMessageBySM2 / EncryptUtil.encryptFileBySM2` 方法默认） | 添加0x04前缀后解密 |
| 8 | C1C2C3 格式，带0x04这个点非压缩标识 | 指定解密Opts后解密 |
| 16 | C1C2C3 格式，不带0x04这个点非压缩标识 | 添加0x04前缀，同时指定解密Opts后解密 |  


**SADK 3.2之后的版本，解密过程**：  
1. 先尝试是否ASN.1格式，如果是，就解密；否则，
2. 当**C1C3C2，不带0x04这个点非压缩标识**的格式处理，如果解密成功，则结束；否则，
3. 当**C1C2C3，不带0x04这个点非压缩标识**的格式处理。

从这个解密流程来看，SADK 3.2+可以解密 SADK 3.2之前的SM2密文，反之不行。

所以如果和SADK 3.2之后的应用交互，加密输出格式可以是ASN.1编码格式，或者是不带0x04这个点非压缩标识的C1C3C2/C1C2C3格式；反之，如果是解密使用SADK 3.2+的应用提供的密文，则要先区分是否是ASN.1格式，是的话就比较简单；不是的话则要指定C1C3C2格式，同时，自己在密文前添加0x04这个点非压缩标识。**互操作的重要前提是知道对方的密文格式**。

### SM2数字信封加解密
互操作性问题主要出在：
1. 数据对称加密所用密钥的SM2密文格式。
2. 对称加密算法的OID。`public static final ASN1ObjectIdentifier id_sm4_CBC = new ASN1ObjectIdentifier("1.2.156.10197.1.104");`。
3. 如果需要用本软件库去解密CFCA生成的SM2数字信封，目前会有问题（从**v0.29.3**开始可以解密）。CFCA实现不符合《GB/T 35275-2017：信息安全技术 SM2密码算法加密签名消息语法规范》，它的**RecipientInfo**默认使用SubjectKeyIdentifier而不是IssuerAndSerialNumber。在SADK 3.7.1.0中，需要指定recipientPolicyType=2（0：从证书扩展中获取SubjectKeyID，找不到抛异常；1：根据公钥数据直接计算SubjectKeyID；2：使用证书的IssuerAndSerialNumber）才会使用IssuerAndSerialNumber。正常情况下，只有CA证书才一定会在证书扩展中有SubjectKeyID信息。如果要产生和CFCA一样的加密信封，请使用`pkcs7.EnvelopeMessageCFCA`方法。

**v0.29.6**之后，请直接使用
* `cfca.EnvelopeMessage`
* `cfca.OpenEnvelopedMessage`
* `cfca.EnvelopeMessageLegacy`
* `cfca.OpenEnvelopedMessageLegacy`

#### SADK 3.2之前版本
1. 数据对称加密密钥的密文格式为**C1C2C3 格式，不带0x04这个点非压缩标识**。这个不符合《GM/T 0010-2012 SM2密码算法加密签名消息语法规范》以及《GB/T 35275-2017 信息安全技术 SM2密码算法加密签名消息语法规范》。
2. SM4-CBC的OID，使用了["SM4" block cipher](https://oid-rep.orange-labs.fr/get/1.2.156.10197.1.104)，而不是["SMS4-CBC"](https://oid-rep.orange-labs.fr/get/1.2.156.10197.1.104.2)。

本软件库的`pkcs7.EncryptCFCA`方法`DecryptCFCA`方法提供了SADK 3.2之前版本的信封加解密兼容性，记得cipher参数选择`pkcs.SM4`。但是`pkcs7.EncryptCFCA`方法产生的加密信封依然使用IssuerAndSerialNumber作为RecipientInfo。

#### SADK 3.2+版本
1. 数据对称加密密钥的密文格式为**ASN.1编码格式**，这个符合《GB/T 35275-2017 信息安全技术 SM2密码算法加密签名消息语法规范》。
2. SM4-CBC的OID，使用了["SM4" block cipher](https://oid-rep.orange-labs.fr/get/1.2.156.10197.1.104)，而不是["SMS4-CBC"](https://oid-rep.orange-labs.fr/get/1.2.156.10197.1.104.2)。

本软件库的`pkcs7.EncryptSM`方法`Decrypt`方法提供了SADK 3.2+版本的信封加解密兼容性。使用时，请确保`cipher`参数选择`pkcs.SM4`。`pkcs7.EncryptSM`方法符合《GB/T 35275-2017 信息安全技术 SM2密码算法加密签名消息语法规范》，CFCA的SADK可实现相应数据的解密。

本软件库的`pkcs7.EnvelopeMessageCFCA`方法提供了CFCA SADK更兼容的实现，也就是recipientPolicyType=0。

从SADK 的向下兼容性来看，SADK 3.2+能够解密SADK 3.2之前版本的数字信封加密数据，反之不行。

### SM2 PKCS7签名数据
`cfca.sadk.util.p7SignMessageAttach / cfca.sadk.util.p7SignMessageDetach`，对应`pkcs7.SignWithoutAttr`，如果要Detach签名，调用`Finish`之前调用`Detach`就行。

`cfca.sadk.util.p7SignFileAttach / cfca.sadk.util.p7SignFileDetach`类似，只是本软件库不提供对应方法，您可以通过`pkcs7.SignWithoutAttr`自己实现。

参考[cfca sadk 3.0.2.0](https://github.com/emmansun/gmsm/issues/260)

**v0.29.6**之后，请直接使用
* `cfca.SignMessageAttach`
* `cfca.VerifyMessageAttach`
* `cfca.SignMessageDetach`
* `cfca.VerifyMessageDetach`
* `cfca.SignDigestDetach`
* `cfca.VerifyDigestDetach`

### 解密时自动检测？
要穷举、尝试所有可能的密文格式不是不可以，但这会或多或少地影响解密的性能。你要和对方集成，还是知己知彼比较好，对于加解密来说，对用户透明不代表是好事。本软件库的SM2解密也实现了一定的自动检测（通过首字节判断，基于首字节只有固定那几个的假设）：
* 0x30 - ASN.1格式。
* 0x04 - C1为非压缩点格式，具体是C1C3C2还是C1C2C3取决于解密时的选项参数，默认为C1C3C2。
* 0x02/0x03 - C1为压缩点格式，具体是C1C3C2还是C1C2C3取决于解密时的选项参数，默认为C1C3C2。

### 生成双密钥CSR （v0.29.6+）
`cfca.CreateCertificateRequest`，和CFCA SADK不同，调用者需要自行先生成两对密钥对，一对用于签名证书，一对用于加解密CFCA生成的加密用私钥文件（CFCA加密，申请者解密）。这个方法对应CFCA的`cfca.sadk.util.P10Request.generateDoublePKCS10Request`方法。按我的理解，非国密（RSA）应该不需要支持这种双密钥对机制，不过既然**CFCA SADK**支持，本软件库从**v0.30.0**开始也支持。

使用`cfca.ParseEscrowPrivateKey`解析CFCA返回的加密用私钥。

### SM2私钥、证书的解析
这个是CFCA自定义的，未见相关标准，可以通过`cfca.ParseSM2`来解析。`cfca.ParseSM2`函数只接受**DER**编码的二进制数据，如果你的数据是**base64**编码的，请先自行解码。
