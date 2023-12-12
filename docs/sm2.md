# 参考标准
* 《GB/T 32918.1-2016 信息安全技术 SM2椭圆曲线公钥密码算法 第1部分：总则》
* 《GB/T 32918.2-2016 信息安全技术 SM2椭圆曲线公钥密码算法 第2部分：数字签名算法》
* 《GB/T 32918.3-2016 信息安全技术 SM2椭圆曲线公钥密码算法 第3部分：密钥交换协议》
* 《GB/T 32918.4-2016 信息安全技术 SM2椭圆曲线公钥密码算法 第4部分：公钥加密算法》
* 《GB/T 32918.5-2016 信息安全技术 SM2椭圆曲线公钥密码算法 第5部分：参数定义》
* 《GB/T 35276-2017 信息安全技术 SM2密码算法使用规范》

您可以从[国家标准全文公开系统](https://openstd.samr.gov.cn/)在线阅读这些标准。

# 概述
既然是椭圆曲线公钥密码算法，它就和NIST P系列椭圆曲线公钥密码算法类似，特别是P-256。NIST P 系列椭圆曲线公钥密码算法主要用于数字签名和密钥交换，NIST没有定义基于椭圆曲线的公钥加密算法标准，[SEC 1: Elliptic Curve Cryptography](https://www.secg.org/sec1-v2.pdf)第五章定义了“Elliptic Curve Integrated Encryption Scheme (ECIES)”，不过应用不广。感兴趣的同学可以进一步对比一下：

| SM2 | SEC 1 |
| :--- | :--- |
| 数字签名算法 | ECDSA |
| 密钥交换协议 | ECMQV |
| 公钥加密算法 | ECIES |

# SM2公私钥对
SM2公私钥对的话，要么是自己产生，要么是别的系统产生后通过某种方式传输给您的。

## SM2公私钥对的生成
您可以通过调用```sm2.GenerateKey```方法产生SM2公私钥对，SM2的私钥通过组合方式扩展了```ecdsa.PrivateKey```，用于定义一些SM2特定的方法：
```go
// PrivateKey represents an ECDSA SM2 private key.
// It implemented both crypto.Decrypter and crypto.Signer interfaces.
type PrivateKey struct {
	ecdsa.PrivateKey
}
```
SM2的公钥类型沿用了```ecdsa.PublicKey```结构。

## SM2公钥的解析、构造
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
	// Create public key from point (uncompressed)
	publicKeyCopy := new(ecdsa.PublicKey)
	publicKeyCopy.Curve = sm2.P256()
	publicKeyCopy.X, publicKeyCopy.Y = elliptic.Unmarshal(publicKeyCopy.Curve, pointBytes)

```
当然，您也可以使用ecdh包下的方法```ecdh.P256().NewPublicKey```来构造，目前只支持非压缩方式。

## SM2私钥的解析、构造
私钥的封装格式主要有以下几种，[相关讨论](https://github.com/emmansun/gmsm/issues/104)：  
* RFC 5915 / SEC1 - http://www.secg.org/sec1-v2.pdf
* PKCS#12
* PKCS#8
* PKCS#7
* CFCA自定义封装
* 《GB/T 35276-2017 信息安全技术 SM2密码算法使用规范》

所以，当您拿到一个密钥文件，您需要知道它的封装格式，然后选用合适的方法。PEM编码的密钥文本通常第一行会有相关信息。如果您得到的是一个ASN.1编码，那可能需要通过ASN.1结构和一些其中的OID来判断了。私钥信息是非常关键的信息，通常密钥文件被加密保护。可能是标准落后于应用的原因，目前这一块的互操作性可能差一点。

| 封装格式 | 解析方法 |
| :--- | :--- |
| RFC 5915 / SEC1 | ```smx509.ParseSM2PrivateKey``` |
| PKCS#12 | 使用 github.com/emmansun/go-pkcs12 解析 |
| PKCS#8 | ```smx509.ParsePKCS8PrivateKey```可以处理未加密的；```pkcs8.ParsePKCS8PrivateKeySM2```可以处理未加密的，也可以处理加密的 |
| PKCS#7 | Cryptographic Message Syntax, 可以参考github.com/emmansun/pkcs7/sign_enveloped_test.go中的```TestParseSignedEvnvelopedData```，测试数据来自 https://www.gmcert.org/ |
| CFCA自定义封装 | 顾名思义，这个封装是CFCA特定的，修改自PKCS#12，使用```cfca.ParseSM2```方法来解析 |
|《GB/T 35276-2017 信息安全技术 SM2密码算法使用规范》| 这个规范还比较新，可能实现的系统比较少，而且加密方是使用您已知的SM2公钥加密对称加密密钥的（类似信封加密），而不是基于密码/口令的KDF方法来产生对称加密密钥。使用```sm2.ParseEnvelopedPrivateKey```解析 |

有些系统可能会直接存储、得到私钥的字节数组，那么您可以使用如下方法来构造私钥：
```go
	bytes, _ := hex.DecodeString("4e85afbc996fdc67b4f05880bd9c0d037932649215ae10cf7085720b6571054c")
	d := new(big.Int).SetBytes(bytes)
	// Create private key from *big.Int
	priv := new(PrivateKey)
	priv.Curve = sm2.P256()
	priv.D = d
	priv.PublicKey.X, priv.PublicKey.Y = priv.ScalarBaseMult(priv.D.Bytes())
```
当然，你也可以使用ecdh包的方法```ecdh.P256().NewPrivateKey```来构造私钥，您要确保输入的字节数组是256位（16字节）的，如果不是，请先自行处理。

# 数字签名算法
您可以直接使用sm2私钥的签名方法```Sign```：
```go
// This is a reference method to force SM2 standard with SDK [crypto.Signer].
func ExamplePrivateKey_Sign_forceSM2() {
	toSign := []byte("ShangMi SM2 Sign Standard")
	// real private key should be from secret storage
	privKey, _ := hex.DecodeString("6c5a0a0b2eed3cbec3e4f1252bfe0e28c504a1c6bf1999eebb0af9ef0f8e6c85")
	d := new(big.Int).SetBytes(privKey)
	testkey := new(sm2.PrivateKey)
	testkey.Curve = sm2.P256()
	testkey.D = d
	testkey.PublicKey.X, testkey.PublicKey.Y = testkey.ScalarBaseMult(testkey.D.Bytes())

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
	testkey := new(ecdsa.PublicKey)
	testkey.Curve = sm2.P256()
	testkey.X, testkey.Y = elliptic.Unmarshal(testkey.Curve, keypoints)

	toSign := []byte("ShangMi SM2 Sign Standard")
	signature, _ := hex.DecodeString("304402205b3a799bd94c9063120d7286769220af6b0fa127009af3e873c0e8742edc5f890220097968a4c8b040fd548d1456b33f470cabd8456bfea53e8a828f92f6d4bdcd77")

	ok := sm2.VerifyASN1WithSM2(testkey, nil, toSign, signature)

	fmt.Printf("%v\n", ok)
	// Output: true
}
```

# 密钥交换协议
这里有两个实现，一个是传统实现，位于sm2包中；另外一个参考最新go语言的实现在ecdh包中。在这里不详细介绍使用方法，一般只有tls/tlcp才会用到，普通应用通常不会涉及这一块，感兴趣的话可以参考github.com/Trisia/gotlcp中的应用。

# 公钥加密算法
请牢记，非对称加密算法通常不用于加密大量数据，而是用来加密对称加密密钥，我们在tlcp以及信封加密机制中能找到这种用法。

SM2公钥加密算法支持的密文编码格式有两种：  
* 简单串接方式: C1C3C2，曾经老的标准为 C1C2C3
* ASN.1格式

SM2公钥加密示例：
```go
func ExampleEncryptASN1() {
	// real public key should be from cert or public key pem file
	keypoints, _ := hex.DecodeString("048356e642a40ebd18d29ba3532fbd9f3bbee8f027c3f6f39a5ba2f870369f9988981f5efe55d1c5cdf6c0ef2b070847a14f7fdf4272a8df09c442f3058af94ba1")
	testkey := new(ecdsa.PublicKey)
	testkey.Curve = sm2.P256()
	testkey.X, testkey.Y = elliptic.Unmarshal(testkey.Curve, keypoints)

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
	d := new(big.Int).SetBytes(privKey)
	testkey := new(sm2.PrivateKey)
	testkey.Curve = sm2.P256()
	testkey.D = d
	testkey.PublicKey.X, testkey.PublicKey.Y = testkey.ScalarBaseMult(testkey.D.Bytes())

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

# 与KMS集成
国内云服务商的KMS服务大都提供SM2密钥，我们一般调用其API进行签名和解密，而验签和加密操作，一般在本地用公钥即可完成。不过需要注意的是，KMS提供的签名通常需要您在本地进行hash操作，而sm2签名的hash又比较特殊，下面示例供参考（将在下个发布版本**v0.24.0**中公开此函数```sm2.CalculateSM2Hash```）：  
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
