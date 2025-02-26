# SM2椭圆曲线公钥密码算法应用指南

## 参考标准
* 《GB/T 32918.1-2016 信息安全技术 SM2椭圆曲线公钥密码算法 第1部分：总则》
* 《GB/T 32918.2-2016 信息安全技术 SM2椭圆曲线公钥密码算法 第2部分：数字签名算法》
* 《GB/T 32918.3-2016 信息安全技术 SM2椭圆曲线公钥密码算法 第3部分：密钥交换协议》
* 《GB/T 32918.4-2016 信息安全技术 SM2椭圆曲线公钥密码算法 第4部分：公钥加密算法》
* 《GB/T 32918.5-2017 信息安全技术 SM2椭圆曲线公钥密码算法 第5部分：参数定义》
* 《GB/T 35276-2017 信息安全技术 SM2密码算法使用规范》
* 《GB/T 33560-2017 信息安全技术 密码应用标识规范》
* 《GB/T 35275-2017 信息安全技术 SM2密码算法加密签名消息语法规范》(对应PKCS#7)

您可以从[国家标准全文公开系统](https://openstd.samr.gov.cn/)在线阅读这些标准。

## 概述
SM2既然是椭圆曲线公钥密码算法，它就和NIST P系列椭圆曲线公钥密码算法类似，特别是P-256。NIST P 系列椭圆曲线公钥密码算法主要用于数字签名和密钥交换，NIST没有定义基于椭圆曲线的公钥加密算法标准，[SEC 1: Elliptic Curve Cryptography](https://www.secg.org/sec1-v2.pdf)第五章定义了“Elliptic Curve Integrated Encryption Scheme (ECIES)”，不过应用不广。SM2公钥加密算法与其相似，只是MAC不同。感兴趣的同学可以进一步对比一下：

| SM2 | SEC 1 |
| :--- | :--- |
| 数字签名算法 | ECDSA |
| 密钥交换协议 | ECMQV |
| 公钥加密算法 | ECIES |

**注**：最新的阿里KMS支持ECIES，难道客户有这个需求？
ECIES_DH_SHA_1_XOR_HMAC：遵循[SEC 1: Elliptic Curve Cryptography, Version 2.0](https://www.secg.org/sec1-v2.pdf)标准，密钥协商算法采用ECDH，密钥派生算法采用 KDF2 with SHA-1，MAC算法采用HMAC-SHA-1，对称加密算法采用XOR。

**业界对RSA非对称加密的安全性担忧与日俱增**：  
* [The Marvin Attack](https://people.redhat.com/~hkario/marvin/)
* [CVE-2023-45287 Detail](https://nvd.nist.gov/vuln/detail/CVE-2023-45287)
* [Vulnerability Report: GO-2023-2375](https://pkg.go.dev/vuln/GO-2023-2375)
* [Seriously, stop using RSA](https://blog.trailofbits.com/2019/07/08/fuck-rsa/)

## SM2公私钥对
SM2公私钥对的话，要么是自己产生，要么是别的系统产生后通过某种方式传输给您的。

### SM2公私钥对的生成
您可以通过调用```sm2.GenerateKey```方法产生SM2公私钥对，SM2的私钥通过组合方式扩展了```ecdsa.PrivateKey```，用于定义一些SM2特定的方法：
```go
// PrivateKey represents an ECDSA SM2 private key.
// It implemented both crypto.Decrypter and crypto.Signer interfaces.
type PrivateKey struct {
	ecdsa.PrivateKey
	...
}
```
SM2的公钥类型沿用了```ecdsa.PublicKey```结构。注意：Go从v1.20开始，```ecdsa.PublicKey```增加了```func (k *PublicKey) ECDH() (*ecdh.PublicKey, error)```方法，这个方法对SM2的公钥不适用，SM2公钥请使用```func PublicKeyToECDH(k *ecdsa.PublicKey) (*ecdh.PublicKey, error)```。

### SM2公钥的解析、构造
通常情况下，公钥是通过PEM编码的文本传输的，您可以通过两步获得公钥：   
* 获得PEM中的block
* 解析block中的公钥

```go
func getPublicKey(pemContent []byte) (any, error) {
	block, _ := pem.Decode(pemContent)
	if block == nil {
		return nil, errors.New("Failed to parse PEM block")
	}
	return smx509.ParsePKIXPublicKey(block.Bytes)
}
```
由于```smx509.ParsePKIXPublicKey```返回any类型，您需要通过```pub, ok := publicKey.(*ecdsa.PublicKey)```转型。

有些应用可能会直接存储公钥的曲线点X, Y 坐标值，这时候，您可以通过以下类似方法构造公钥（假设输入的是点的非压缩序列化字节数组）：
```go
func ExampleNewPublicKey() {
	keypoints, _ := hex.DecodeString("048356e642a40ebd18d29ba3532fbd9f3bbee8f027c3f6f39a5ba2f870369f9988981f5efe55d1c5cdf6c0ef2b070847a14f7fdf4272a8df09c442f3058af94ba1")
	pub, err := sm2.NewPublicKey(keypoints)
	if err != nil {
		log.Fatalf("fail to new public key %v", err)
	}
	fmt.Printf("%x\n", elliptic.Marshal(sm2.P256(), pub.X, pub.Y))
	// Output: 048356e642a40ebd18d29ba3532fbd9f3bbee8f027c3f6f39a5ba2f870369f9988981f5efe55d1c5cdf6c0ef2b070847a14f7fdf4272a8df09c442f3058af94ba1
}
```
当然，您也可以使用ecdh包下的方法```ecdh.P256().NewPublicKey```来构造，目前只支持非压缩方式。

### SM2私钥的解析、构造
私钥的封装格式主要有以下几种，[相关讨论](https://github.com/emmansun/gmsm/issues/104)：  
* RFC 5915 / SEC1 - http://www.secg.org/sec1-v2.pdf
* PKCS#12
* PKCS#8
* PKCS#7（《GB/T 35275-2017 信息安全技术 SM2密码算法加密签名消息语法规范》）
* CFCA自定义封装
* 《GB/T 35276-2017 信息安全技术 SM2密码算法使用规范》  

（存在于智能密码钥匙中，符合《GB/T 35291-2017 信息安全技术 智能密码钥匙应用接口规范》的，不在这里说明。）

所以，当您拿到一个密钥文件，您需要知道它的封装格式，然后选用合适的方法。PEM编码的密钥文本通常第一行会有相关信息。如果您得到的是一个ASN.1编码，那可能需要通过ASN.1结构和一些其中的OID来判断了。私钥信息是非常关键的信息，通常密钥文件被加密保护。可能是标准落后于应用的原因，目前这一块的互操作性可能差一点。

| 封装格式 | 解析方法 |
| :--- | :--- |
| RFC 5915 / SEC1 | ```smx509.ParseSM2PrivateKey``` |
| PKCS#12 | 使用 github.com/emmansun/go-pkcs12 解析 |
| PKCS#8 | ```smx509.ParsePKCS8PrivateKey```可以处理未加密的；```pkcs8.ParsePKCS8PrivateKeySM2```可以处理未加密的，也可以处理加密的 |
| PKCS#7 | Cryptographic Message Syntax, 可以参考github.com/emmansun/pkcs7/sign_enveloped_test.go中的```TestParseSignedEvnvelopedData```，测试数据来自 https://www.gmcert.org/ |
| CFCA自定义封装 | 顾名思义，这个封装是CFCA特定的，修改自PKCS#12，使用```cfca.ParseSM2```方法来解析 |
|《GB/T 35276-2017 信息安全技术 SM2密码算法使用规范》| 这个规范还比较新，使用```sm2.ParseEnvelopedPrivateKey```解析。典型的应用场景是CA机构返回CSRResponse, 里面包含签名证书、CA生成的SM2加密私钥以及相应的SM2加密证书，其中SM2加密私钥就用该规范定义的方式加密封装。请参考《GM/T 0092-2020 基于SM2算法的证书申请语法规范》 |

有些系统可能会直接存储、得到私钥的字节数组，那么您可以使用如下方法来构造私钥：
```go
func ExampleNewPrivateKey() {
	keyBytes, _ := hex.DecodeString("6c5a0a0b2eed3cbec3e4f1252bfe0e28c504a1c6bf1999eebb0af9ef0f8e6c85")
	priv, err := sm2.NewPrivateKey(keyBytes)
	if err != nil {
		log.Fatalf("fail to new private key %v", err)
	}
	fmt.Printf("%x\n", priv.D.Bytes())
	// Output: 6c5a0a0b2eed3cbec3e4f1252bfe0e28c504a1c6bf1999eebb0af9ef0f8e6c85
}

func ExampleNewPrivateKeyFromInt() {
	key := big.NewInt(0x123456)
	priv, err := sm2.NewPrivateKeyFromInt(key)
	if err != nil {
		log.Fatalf("fail to new private key %v", err)
	}
	fmt.Printf("%x\n", priv.D.Bytes())
	// Output: 123456
}
```
当然，你也可以使用ecdh包的方法```ecdh.P256().NewPrivateKey```来构造私钥，您要确保输入的字节数组是256位（32字节）的，如果不是，请先自行处理。

### 关于《GM/T 0091-2020 基于口令的密钥派生规范》
这个规范就是[RFC8018 PKCS#5](https://datatracker.ietf.org/doc/html/rfc8018) 国密定制版，其中PBES/PBKDF/PBMAC使用了不同的OID，但是这些OID似乎没有注册过。而且表A.1 中**id-hmacWithSM3**的OID为没有注册过的**1.2.156.10197.1.401.3.1**，和我们常用的**1.2.156.10197.1.401.2**不一致，也与该文档本身附录C不一致。不知道哪个产品遵从了这个行业规范。

| 对象标识符OID | 对象标识符定义 |
| :--- | :--- |
| 1.2.156.10197.6.1.4.1.5 | 基于口令的密钥派生规范 |
| 1.2.156.10197.6.1.4.1.5.1 | 基于口令的密钥派生函数 PBKDF (其实就是PBKDF2) |
| 1.2.156.10197.6.1.4.1.5.2 | 基于口令的加密方案PBES (其实就是PBES2) |
| 1.2.156.10197.6.1.4.1.5.3 | 基于口令的消息鉴别码PBMAC |

规范中让人困惑的地方：
1. 附录 **A.2 伪随机函数** 引入了这个新的**id-hmacWithSM3**的OID**1.2.156.10197.1.401.3.1**
2. 附录 **A.4 基础消息鉴别方案**，给出的实例片段中的OID为**1.2.156.10197.1.401**，让人怀疑这个实例抄的是**PKCS12-MAC**，而不是**PBMAC1**。
3. 附录 **B.2 PBES结构**，**PBES-Encs**竟然给出了**pbeWithSM3AndSM4-CBC OJBECTIDENTIFIER ::= {1.2.156.10197.6.1.4.1.12.1.1}**，难不成又要抄**PBES1**?
4. 附录 **C. ASN.1 结构定义**，**id-hmacWithSM3**的OID又是**1.2.156.10197.1.401.2**。

## 数字签名算法
您可以直接使用sm2私钥的签名方法```Sign```：
```go
// This is a reference method to force SM2 standard with SDK [crypto.Signer].
func ExamplePrivateKey_Sign_forceSM2() {
	toSign := []byte("ShangMi SM2 Sign Standard")
	// real private key should be from secret storage
	privKey, _ := hex.DecodeString("6c5a0a0b2eed3cbec3e4f1252bfe0e28c504a1c6bf1999eebb0af9ef0f8e6c85")
	testkey, err := sm2.NewPrivateKey(privKey)
	if err != nil {
		log.Fatalf("fail to new private key %v", err)
	}

	// force SM2 sign standard and use default UID
	sig, err := testkey.Sign(rand.Reader, toSign, sm2.DefaultSM2SignerOpts)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error from sign: %s\n", err)
		return
	}

	// Since sign is a randomized function, signature will be
	// different each time.
	fmt.Printf("%x\n", sig)
}
```
我们通过```SignerOpts```参数来指示```toSign```已经是hash值，还是需要进行处理的原始信息。通常情况下，```toSign```传入原始信息、```SignerOpts```传入```sm2.DefaultSM2SignerOpts```。如果将来标准支持自定义的uid，那么您可以通过调用```sm2.NewSM2SignerOption```来构造一个自定义的```SignerOpts```。

当然，您也可以通过调用SM2私钥的```SignWithSM2```方法，区别在于，```Sign```方法是```crypto.Singer```接口中定义的方法，而```SignWithSM2```方法是```sm2.Signer```接口中定义的方法。

您可以使用```sm2.VerifyASN1WithSM2```来校验SM2签名：
```go
func ExampleVerifyASN1WithSM2() {
	// real public key should be from cert or public key pem file
	keypoints, _ := hex.DecodeString("048356e642a40ebd18d29ba3532fbd9f3bbee8f027c3f6f39a5ba2f870369f9988981f5efe55d1c5cdf6c0ef2b070847a14f7fdf4272a8df09c442f3058af94ba1")
	testkey, err := sm2.NewPublicKey(keypoints)
	if err != nil {
		log.Fatalf("fail to new public key %v", err)
	}

	toSign := []byte("ShangMi SM2 Sign Standard")
	signature, _ := hex.DecodeString("304402205b3a799bd94c9063120d7286769220af6b0fa127009af3e873c0e8742edc5f890220097968a4c8b040fd548d1456b33f470cabd8456bfea53e8a828f92f6d4bdcd77")

	ok := sm2.VerifyASN1WithSM2(testkey, nil, toSign, signature)

	fmt.Printf("%v\n", ok)
	// Output: true
}
```

### 如何处理不用Z的签名、验签？
所谓**Z**，就是用户可识别标识符和用户公钥、SM2椭圆曲线参数的杂凑值。其它签名算法如ECDSA是没有这个**Z**的，这也是SM2签名算法难以融入以ECDSA签名算法为主的体系的主因。

#### 签名
也是使用sm2私钥的`Sign`方法，只是```SignerOpts```传入`nil`或者其它非`SM2SignerOption`即可，那么，你自己负责预先计算杂凑值，当然如何计算杂凑值，由你自己说了算了。

#### 验签
调用`sm2.VerifyASN1`方法，同样，你自己负责预先计算杂凑值，确保杂凑算法和签名时使用的杂凑算法保持一致。

### 如何对大文件签名、验签？
解决方案就是对杂凑值进行签名、验签。`sm2.CalculateSM2Hash`并不适合对大文件进行杂凑计算，请使用专门的`hash.Hash`接口实现。

## 密钥交换协议
这里有两个实现，一个是传统实现，位于sm2包中；另外一个参考最新go语言的实现在ecdh包中。在这里不详细介绍使用方法，一般只有tls/tlcp才会用到，普通应用通常不会涉及这一块，感兴趣的话可以参考github.com/Trisia/gotlcp中的应用。

## 公钥加密算法
请牢记，非对称加密算法通常不用于加密大量数据，而是用来加密对称加密密钥，我们在**tlcp**以及**信封加密**机制中能找到这种用法。

SM2公钥加密算法支持的密文编码格式有两种：  
* 简单串接方式: C1C3C2，曾经老的标准为 C1C2C3
* ASN.1格式

SM2公钥加密示例：
```go
func ExampleEncryptASN1() {
	// real public key should be from cert or public key pem file
	keypoints, _ := hex.DecodeString("048356e642a40ebd18d29ba3532fbd9f3bbee8f027c3f6f39a5ba2f870369f9988981f5efe55d1c5cdf6c0ef2b070847a14f7fdf4272a8df09c442f3058af94ba1")
	testkey, err := sm2.NewPublicKey(keypoints)
	if err != nil {
		log.Fatalf("fail to new public key %v", err)
	}

	secretMessage := []byte("send reinforcements, we're going to advance")

	// crypto/rand.Reader is a good source of entropy for randomizing the
	// encryption function.
	rng := rand.Reader

	ciphertext, err := sm2.EncryptASN1(rng, testkey, secretMessage)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error from encryption: %s\n", err)
		return
	}
	// Since encryption is a randomized function, ciphertext will be
	// different each time.
	fmt.Printf("Ciphertext: %x\n", ciphertext)
}
```
如果您需要普通拼接编码输出，您可以调用```sm2.Encrypt```方法，其中```EncrypterOpts```类型参数可以传入nil，表示默认C1C3C2。

sm2包也提供了辅助方法用于密文输出编码格式转换：您可以通过```sm2.ASN1Ciphertext2Plain```方法把ASN.1密文转换为简单拼接输出；反过来，您也可以通过```sm2.PlainCiphertext2ASN1```将简单拼接密文输出转换为ASN.1密文。你还可以通过```sm2.AdjustCiphertextSplicingOrder```方法来改变串接顺序。

SM2公钥加密算法解密示例：
```go
func ExamplePrivateKey_Decrypt() {
	ciphertext, _ := hex.DecodeString("308194022100bd31001ce8d39a4a0119ff96d71334cd12d8b75bbc780f5bfc6e1efab535e85a02201839c075ff8bf761dcbe185c9750816410517001d6a130f6ab97fb23337cce150420ea82bd58d6a5394eb468a769ab48b6a26870ca075377eb06663780c920ea5ee0042be22abcf48e56ae9d29ac770d9de0d6b7094a874a2f8d26c26e0b1daaf4ff50a484b88163d04785b04585bb")

	// real private key should be from secret storage
	privKey, _ := hex.DecodeString("6c5a0a0b2eed3cbec3e4f1252bfe0e28c504a1c6bf1999eebb0af9ef0f8e6c85")
	testkey, err := sm2.NewPrivateKey(privKey)
	if err != nil {
		log.Fatalf("fail to new private key %v", err)
	}

	plaintext, err := testkey.Decrypt(nil, ciphertext, nil)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error from decryption: %s\n", err)
		return
	}

	fmt.Printf("Plaintext: %s\n", string(plaintext))
	// Output: Plaintext: send reinforcements, we're going to advance
}
```
这个SM2私钥的解密方法```Decrypt```，通常情况下，对```crypto.DecrypterOpts```类型参数，您只需传入nil，系统会自己检测输入密文是ASN.1还是普通拼接，但是，如果密文是老旧的C1||C2||C3拼接，请传入相应的```crypto.DecrypterOpts```类型参数，或者您可以先通过上面介绍的辅助函数转换一下。

具体API文档请参考：[API Document](https://godoc.org/github.com/emmansun/gmsm)

### 关于C1C2C3 和 C1C3C2
目前有据可查的是，国家密码管理局2010版SM2标准还是用C1C2C3格式，到了2012年标准就改用了C1C3C2，并延续至今。
其实C1C2C3是符合《SEC 1: Elliptic Curve Cryptography》（May 21, 2009 Version 2.0）Elliptic Curve Integrated Encryption Scheme 5.1.3中的密文输出描述：9. Output C = ($\overline{\text{R}}$, EM, D). Optionally, the ciphertext maybe output as C = $\overline{\text{R}}$ || EM || D. 这里 $\overline{\text{R}}$ 相对于C1, EM相对于C2, D相对于C3。

### 关于点到字节串的转换
我没有找到到哪个文档写有固定64字节转换的。从国家密码管理局2010年版的《SM2椭圆曲线公钥密码算法》，到2012年的GM/T 0003-2012 SM2椭圆曲线公钥密码算法，再到GB/T 32918-2016 信息安全技术 SM2椭圆曲线公钥密码算法，都在第一部分第四章的“点到字节串的转换”有详细说明。这也符合《SEC 1: Elliptic Curve Cryptography》（May 21, 2009 Version 2.0）中2.3.3  Elliptic-Curve-Point-to-Octet-String Conversion的描述。

#### 来自AI的问答
**问: 为什么一些crypto实现中，椭圆曲线点转换为八位字节串时没有使用格式指示符？**  
**答：** 在椭圆曲线密码学（ECC）中，椭圆曲线点转换为八位字节串的方法有多种，通常可以是压缩形式或未压缩形式。格式指示符（也称为前缀）用于表示该点是以压缩形式还是未压缩形式表示。

然而，一些实现可能会出于几个原因选择省略格式指示符：

1. **简洁性**：省略格式指示符可以简化实现过程，因为不需要处理不同形式的点表示。
2. **预设知识**：如果事先知道所有点都将处于某种特定形式（例如，所有点总是未压缩的），则可能会认为格式指示符是不必要的。
3. **兼容性**：并非所有系统或库都支持两种形式的点表示。为了确保最大兼容性，实现可能会选择始终使用一种形式，从而省略格式指示符。
4. **安全性**：在某些情况下，为了防止依赖于点形式的某些类型的攻击，可能会省略格式指示符。

请注意，这些是通用原因，具体原因可能会根据确切的上下文以及使用的特定密码协议或系统而有所不同。

**问：这不会引起互操作性问题吗？**  
**答：** 是的，你说得对。在将椭圆曲线点转换为八位字节串时省略格式指示符，确实可能导致互操作性问题。

当系统需要互操作时，它们必须就数据交换的通用格式达成一致。如果一个系统在编码椭圆曲线点时没有使用格式指示符，而另一个系统期望格式指示符存在，它们将无法正确解释彼此的数据。

这就是为什么像SEC（高效密码学标准）这样的标准会指定使用格式指示符。例如，SEC 1标准指定未压缩点的格式指示符应为0x04，压缩点的格式指示符应为0x02或0x03。

因此，虽然在封闭系统中省略格式指示符可能会简化实现或提供其他好处，但它可能会阻碍与其他系统的互操作性。在编码和解码密码数据时，通常最好遵循已建立的标准，以确保最大的兼容性。

### 性能
从**v0.27.0**开始，对大数据量的加解密做了优化处理，尤其是KDF并行计算。详情请参考[SM2加解密性能](https://github.com/emmansun/gmsm/wiki/SM2%E5%8A%A0%E8%A7%A3%E5%AF%86%E6%80%A7%E8%83%BD)。

## 与KMS集成
国内云服务商的KMS服务大都提供SM2密钥，我们一般调用其API进行签名和解密，而验签和加密操作，一般在本地用公钥即可完成。不过需要注意的是，KMS提供的签名通常需要您在本地进行hash操作，而sm2签名的hash又比较特殊，下面示例供参考（自版本**v0.24.0**开始，您可以直接使用函数```sm2.CalculateSM2Hash```）：  
```go
func calculateSM2Hash(pub *ecdsa.PublicKey, data, uid []byte) ([]byte, error) {
	if len(uid) == 0 {
		uid = defaultUID
	}
	za, err := sm2.CalculateZA(pub, uid)
	if err != nil {
		return nil, err
	}
	md := sm3.New()
	md.Write(za)
	md.Write(data)
	return md.Sum(nil), nil
}
```
公钥加密就没啥特殊，只要确保输出密文的编码格式和KMS一致即可。

## 基于密码硬件，定制SM2私钥
密码硬件（SDF/SKF）中的用户密钥（私钥）通常是无法导出的，但都提供了签名、解密APIs供调用，为了和本软件库集成，需要实现以下接口：

1. `crypto.Signer`，这个接口的实现通常把传入的数据作为哈希值。
2. `crypto.Decrypter`，这个接口用于解密操作。

通常需要实现四个方法：
1. `Public() crypto.PublicKey`
2. `Sign(rand io.Reader, digest []byte, opts SignerOpts) (signature []byte, err error)`
3. `Decrypt(rand io.Reader, msg []byte, opts DecrypterOpts) (plaintext []byte, err error)`

第一个返回公钥的方法是必须要实现的，后面的方法取决于这个KEY的用途。

**注意**：
1. `Sign(rand io.Reader, digest []byte, opts SignerOpts) (signature []byte, err error)`方法通常用于对哈希值作签名，最好遵从以下实现逻辑：检查`opts`是否是`*sm2.SM2SignerOption`类型，如果是，则把传入的`digest`作为原始数据进行处理，具体实现可以参考`sm2.SignASN1`函数。当然，在大多数情况下，直接将数据视为原始数据是可行的。实施者可以根据具体的应用场景灵活处理。
2. 如果密码硬件有自己的随机数源，可以忽略传入的`rand`。
3. 很多设备签名函数通常只接收哈希值，需要调用```sm2.CalculateSM2Hash```或者**SDF**提供的哈希函数计算哈希值。

SDF API请参考《GB/T 36322-2018 密码设备应用接口规范》

## SM2扩展应用
SM2的一些扩展应用，譬如从签名中恢复公钥、半同态加密、环签名等，大多尚处于POC状态，也无相关标准。其它扩展应用（但凡椭圆曲线公钥密码算法能用到的场合），包括但不限于：
* [确定性签名](https://datatracker.ietf.org/doc/html/rfc6979)
* [可验证随机函数ECVRF](https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-vrf-04)
* 盲签名
* 群签名
* 门限签名
* [Pederson承诺](https://crypto.stackexchange.com/questions/64437/what-is-a-pedersen-commitment)

### 从签名中恢复公钥
ECDSA 签名由两个数字（整数）组成：r 和 s。以太坊还引入了额外的变量 v（恢复标识符）。签名可以表示成 {r, s, v}。SM2 签名也由两个数字（整数）组成：r 和 s。签名算法中都只取随机点的X坐标，并对N取模，所以只有签名r和s的情况下，可以恢复出多个公钥。
```go
// RecoverPublicKeysFromSM2Signature recovers two or four SM2 public keys from a given signature and hash.
// It takes the hash and signature as input and returns the recovered public keys as []*ecdsa.PublicKey.
// If the signature or hash is invalid, it returns an error.
// The function follows the SM2 algorithm to recover the public keys.
func RecoverPublicKeysFromSM2Signature(hash, sig []byte) ([]*ecdsa.PublicKey, error)
```
返回的结果：  
* 公钥0 - Rx = (r - e) mod N; Ry是偶数（compressFlag = 2）
* 公钥1 - Rx = (r - e) mod N; Ry是奇数（compressFlag = 3）
* 公钥2 - Rx = ((r - e) mod N) + N; Ry是偶数（compressFlag = 2）
* 公钥3 - Rx = ((r - e) mod N) + N; Ry是奇数（compressFlag = 3）  

Rx, Ry代表随机点R的X,Y坐标值。绝大多数情况下，只会返回两个公钥，后两者只有当(r - e) mod N的值小于P-1-N时才可能。

### 半同态加解密
EC-ElGamal with SM2的半同态加密（Partially Homomorphic Encryption, PHE）, 支持uint32 或者 int32类型。[Partially Homomorphic Encryption, EC-ElGamal with SM2](https://github.com/emmansun/sm2elgamal).

### 环签名
[Ring Signature Schemes Based on SM2 Digital Signature Algorithm](https://github.com/emmansun/sm2rsign).
