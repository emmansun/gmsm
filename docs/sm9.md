# SM9标识密码算法应用指南

## 参考标准
* 《GB/T 38635.1-2020  信息安全技术 SM9标识密码算法 第1部分：总则》
* 《GB/T 38635.2-2020 信息安全技术 SM9标识密码算法 第2部分：算法》
* 《GB/T 41389-2022 信息安全技术 SM9密码算法使用规范》
* 《GM/T 0086-2020 基于SM9标识密码算法的密钥管理系统技术规范》

您可以从[国家标准全文公开系统](https://openstd.samr.gov.cn/)在线阅读这些标准。

## 概述
SM9算法是一种基于双线性对的标识密码算法（简称“IBC”），由数字签名算法、标识加密算法、密钥协商协议三部分组成，相比于传统密码体系，SM9密码系统号称的**最大的优势就是无需证书、易于使用、易于管理、总体拥有成本低**，但这显然过于理想化：
* **KGC**中心的标准化与权威性。标志密码算法依然需要主密钥，需要中心化的KGC，私有系统可能自己搞个简单点的服务就行，但作为公共、公开服务系统，没有标准化与权威性是不行的。
* 用户私钥依然有被盗、遗失的风险，所以依然有用户标识作废、重新启用等需求。这也意味着客户端依然需要访问**KGC**的公开参数服务，查询用户标识状态。
* **《GM/T 0086-2020 基于SM9标识密码算法的密钥管理系统技术规范》** 定义了相关规范，但不知道有没有建成相关系统。且这和传统的公钥体系（PKI）相比有何优势？  

同时，SM9标识密码算法还有以下问题：
* 基于双线性对的标识密码算法的实现复杂度和性能问题（本软件库的SM9实现，其签名、验签性能不到SM2的十分之一）。
* SM9标识密码算法选择的bn256曲线安全问题：[128位安全性挑战](https://moderncrypto.org/mail-archive/curves/2016/000740.html)？

上述只是简单的探讨，没有贬低SM9标识密码算法的意思。

## 主公私钥对
SM9标识密码算法用于签名和加密的主公私钥对是分开的，需要各自独立生成：
* ```sm9.GenerateSignMasterKey```用于生成签名主密钥对。
* ```sm9.GenerateEncryptMasterKey```用于生成加密主密钥对。

其中签名主公钥是G2上的点，加密主公钥是G1上的点，而签名、加密主私钥都是一个随机大整数。

主公私钥的ASN.1数据格式定义请参考《GB/T 41389-2022 信息安全技术 SM9密码算法使用规范》，和椭圆曲线的公私钥ASN.1数据格式类似。本软件实现了相应的Marshal/Unmarshal方法。

## 用户私钥
用户的签名私钥由签名主私钥、用户标识生成：```(master *SignMasterPrivateKey) GenerateUserKey(uid []byte, hid byte) (*SignPrivateKey, error)```，它是G1上的点。

用户的加密私钥由加密主私钥、用户标识生成：```func (master *EncryptMasterPrivateKey) GenerateUserKey(uid []byte, hid byte) (*EncryptPrivateKey, error)```，它是G2上的点。

《GB/T 41389-2022 信息安全技术 SM9密码算法使用规范》中 hid 定义如下：
* hid = 1，签名
* hid = 3，加密

本软件实现没有硬编码**hid**的值。

用户签名、加密私钥的ASN.1数据格式定义请参考《GB/T 41389-2022 信息安全技术 SM9密码算法使用规范》，和椭圆曲线点的ASN.1数据格式类似。本软件实现了相应的Marshal/Unmarshal方法。

目前```smx509```中实现的```MarshalPKCS8PrivateKey/ParsePKCS8PrivateKey```没有相关标准，只是为了和[gmssl](https://github.com/guanzhi/GmSSL)互操作验证，请参考[sm9:【feature】是否考虑支持 pem 格式的公私钥输出](https://github.com/emmansun/gmsm/issues/86)。
```go
func TestMarshalPKCS8SM9SignPrivateKey(t *testing.T) {
	masterKey, err := sm9.GenerateSignMasterKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	privateKey, err := masterKey.GenerateUserKey([]byte("emmansun"), 0x01)
	if err != nil {
		t.Fatal(err)
	}
	res, err := MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		t.Fatal(err)
	}
	privateKey1, err := ParsePKCS8PrivateKey(res)
	if err != nil {
		t.Fatal(err)
	}
	privateKey2, ok := privateKey1.(*sm9.SignPrivateKey)
	if !ok {
		t.Fatalf("not expected key")
	}
	if !privateKey.PrivateKey.Equal(privateKey2.PrivateKey) ||
		!privateKey.MasterPublicKey.Equal(privateKey2.MasterPublicKey) {
		t.Fatalf("not same key")
	}
}

func TestMarshalPKCS8SM9EncPrivateKey(t *testing.T) {
	masterKey, err := sm9.GenerateEncryptMasterKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	privateKey, err := masterKey.GenerateUserKey([]byte("emmansun"), 0x01)
	if err != nil {
		t.Fatal(err)
	}
	res, err := MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		t.Fatal(err)
	}
	privateKey1, err := ParsePKCS8PrivateKey(res)
	if err != nil {
		t.Fatal(err)
	}
	privateKey2, ok := privateKey1.(*sm9.EncryptPrivateKey)
	if !ok {
		t.Fatalf("not expected key")
	}
	if !privateKey.PrivateKey.Equal(privateKey2.PrivateKey) ||
		!privateKey.MasterPublicKey.Equal(privateKey2.MasterPublicKey) {
		t.Fatalf("not same key")
	}
}

func TestMarshalPKCS8SM9SignMasterPrivateKey(t *testing.T) {
	masterKey, err := sm9.GenerateSignMasterKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	res, err := MarshalPKCS8PrivateKey(masterKey)
	if err != nil {
		t.Fatal(err)
	}
	masterKey1, err := ParsePKCS8PrivateKey(res)
	if err != nil {
		t.Fatal(err)
	}
	masterKey2, ok := masterKey1.(*sm9.SignMasterPrivateKey)
	if !ok {
		t.Fatalf("not expected key")
	}
	masterKey2.MasterPublicKey.Marshal()
	if !(masterKey.D.Cmp(masterKey2.D) == 0 && masterKey.MasterPublicKey.Equal(masterKey2.MasterPublicKey)) {
		t.Fatalf("not same key")
	}
}

func TestMarshalPKCS8SM9EncMasterPrivateKey(t *testing.T) {
	masterKey, err := sm9.GenerateEncryptMasterKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	res, err := MarshalPKCS8PrivateKey(masterKey)
	if err != nil {
		t.Fatal(err)
	}
	masterKey1, err := ParsePKCS8PrivateKey(res)
	if err != nil {
		t.Fatal(err)
	}
	masterKey2, ok := masterKey1.(*sm9.EncryptMasterPrivateKey)
	if !ok {
		t.Fatalf("not expected key")
	}
	masterKey2.MasterPublicKey.Marshal()
	if !(masterKey.D.Cmp(masterKey2.D) == 0 && masterKey.MasterPublicKey.Equal(masterKey2.MasterPublicKey)) {
		t.Fatalf("not same key")
	}
}
```

## 数字签名
使用用户签名私钥进行签名，使用签名主公钥和用户标识进行验签：
```go
func ExampleSignPrivateKey_Sign() {
	// real user sign private key should be from secret storage.
	kb, _ := hex.DecodeString("0130E78459D78545CB54C587E02CF480CE0B66340F319F348A1D5B1F2DC5F4")
	var b cryptobyte.Builder
	b.AddASN1BigInt(new(big.Int).SetBytes(kb))
	kb, _ = b.Bytes()
	masterkey := new(sm9.SignMasterPrivateKey)
	err := masterkey.UnmarshalASN1(kb)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error from UnmarshalASN1: %s\n", err)
		return
	}
	hid := byte(0x01)
	uid := []byte("Alice")
	userKey, err := masterkey.GenerateUserKey(uid, hid)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error from GenerateUserKey: %s\n", err)
		return
	}

	// sm9 sign
	hash := []byte("Chinese IBS standard")
	sig, err := userKey.Sign(rand.Reader, hash, nil)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error from Sign: %s\n", err)
		return
	}

	// Since sign is a randomized function, signature will be
	// different each time.
	fmt.Printf("%x\n", sig)
}

func ExampleVerifyASN1() {
	// get master public key, can be from pem
	masterPubKey := new(sm9.SignMasterPublicKey)
	keyBytes, _ := hex.DecodeString("03818200049f64080b3084f733e48aff4b41b565011ce0711c5e392cfb0ab1b6791b94c40829dba116152d1f786ce843ed24a3b573414d2177386a92dd8f14d65696ea5e3269850938abea0112b57329f447e3a0cbad3e2fdb1a77f335e89e1408d0ef1c2541e00a53dda532da1a7ce027b7a46f741006e85f5cdff0730e75c05fb4e3216d")
	err := masterPubKey.UnmarshalASN1(keyBytes)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error from UnmarshalASN1: %s\n", err)
		return
	}
	hid := byte(0x01)
	uid := []byte("Alice")
	hash := []byte("Chinese IBS standard")
	sig, _ := hex.DecodeString("30660420b0d0c0bb1b57ea0d5b51cb5c96be850b8c2eef6b0fff5fcccb524b972574e6eb03420004901819575c9211c7b4e6e137794d23d0095608bcdad5c82dbff05777c5b49c763e4425acea2aaedf9e48d4784b4e4a5621cc3663fe0aae44dcbeac183fee9b0f")
	ok := sm9.VerifyASN1(masterPubKey, uid, hid, hash, sig)

	fmt.Printf("%v\n", ok)
	// Output: true
}

func ExampleSignMasterPublicKey_Verify() {
	// get master public key, can be from pem
	masterPubKey := new(sm9.SignMasterPublicKey)
	keyBytes, _ := hex.DecodeString("03818200049f64080b3084f733e48aff4b41b565011ce0711c5e392cfb0ab1b6791b94c40829dba116152d1f786ce843ed24a3b573414d2177386a92dd8f14d65696ea5e3269850938abea0112b57329f447e3a0cbad3e2fdb1a77f335e89e1408d0ef1c2541e00a53dda532da1a7ce027b7a46f741006e85f5cdff0730e75c05fb4e3216d")
	err := masterPubKey.UnmarshalASN1(keyBytes)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error from UnmarshalASN1: %s\n", err)
		return
	}
	hid := byte(0x01)
	uid := []byte("Alice")
	hash := []byte("Chinese IBS standard")
	sig, _ := hex.DecodeString("30660420b0d0c0bb1b57ea0d5b51cb5c96be850b8c2eef6b0fff5fcccb524b972574e6eb03420004901819575c9211c7b4e6e137794d23d0095608bcdad5c82dbff05777c5b49c763e4425acea2aaedf9e48d4784b4e4a5621cc3663fe0aae44dcbeac183fee9b0f")
	ok := masterPubKey.Verify(uid, hid, hash, sig)

	fmt.Printf("%v\n", ok)
	// Output: true
}
```
签名结果ASN.1格式请参考参考《GB/T 41389-2022 信息安全技术 SM9密码算法使用规范》。

## 密钥封装
使用加密主公钥和目标用户标识进行密钥封装，使用用户加密私钥和用户标识进行解封：
```go
func ExampleEncryptMasterPublicKey_WrapKey() {
	// get master public key, can be from pem
	masterPubKey := new(sm9.EncryptMasterPublicKey)
	keyBytes, _ := hex.DecodeString("03420004787ed7b8a51f3ab84e0a66003f32da5c720b17eca7137d39abc66e3c80a892ff769de61791e5adc4b9ff85a31354900b202871279a8c49dc3f220f644c57a7b1")
	err := masterPubKey.UnmarshalASN1(keyBytes)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error from UnmarshalASN1: %s\n", err)
		return
	}
	hid := byte(0x03)
	uid := []byte("Bob")
	key, cipherDer, err := masterPubKey.WrapKey(rand.Reader, uid, hid, 32)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error from WrapKeyASN1: %s\n", err)
		return
	}

	// Since WrapKey is a randomized function, result will be
	// different each time.
	fmt.Printf("%s %s\n", hex.EncodeToString(key), hex.EncodeToString(cipherDer))
}

func ExampleEncryptPrivateKey_UnwrapKey() {
	// real user encrypt private key should be from secret storage, e.g. password protected pkcs8 file
	kb, _ := hex.DecodeString("038182000494736acd2c8c8796cc4785e938301a139a059d3537b6414140b2d31eecf41683115bae85f5d8bc6c3dbd9e5342979acccf3c2f4f28420b1cb4f8c0b59a19b1587aa5e47570da7600cd760a0cf7beaf71c447f3844753fe74fa7ba92ca7d3b55f27538a62e7f7bfb51dce08704796d94c9d56734f119ea44732b50e31cdeb75c1")
	userKey := new(sm9.EncryptPrivateKey)
	err := userKey.UnmarshalASN1(kb)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error from UnmarshalASN1: %s\n", err)
		return
	}

	cipherDer, _ := hex.DecodeString("0342000447689629d1fa57e8def447f42b75e28518a1b692891528ca596f7bcbf581c7cf429ed01b114ce157ed4eadd0b2ded9a7e475e347f67b6affa3a6cf654573f978")
	key, err := userKey.UnwrapKey([]byte("Bob"), cipherDer, 32)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error from UnwrapKey: %s\n", err)
		return
	}
	fmt.Printf("%s\n", hex.EncodeToString(key))
	// Output: 270c42505bca90a8084064ea8af279364405a8195f30664082ead3d6991ed70f
}
```

密钥封装结果ASN.1格式请参考参考《GB/T 41389-2022 信息安全技术 SM9密码算法使用规范》。

## 公钥加密算法
使用加密主公钥和目标用户标识进行加密，使用用户加密私钥和用户标识进行解密：
```go
func ExampleEncryptMasterPublicKey_Encrypt() {
	// get master public key, can be from pem
	masterPubKey := new(sm9.EncryptMasterPublicKey)
	keyBytes, _ := hex.DecodeString("03420004787ed7b8a51f3ab84e0a66003f32da5c720b17eca7137d39abc66e3c80a892ff769de61791e5adc4b9ff85a31354900b202871279a8c49dc3f220f644c57a7b1")
	err := masterPubKey.UnmarshalASN1(keyBytes)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error from UnmarshalASN1: %s\n", err)
		return
	}
	hid := byte(0x03)
	uid := []byte("Bob")

	ciphertext, err := masterPubKey.Encrypt(rand.Reader, uid, hid, []byte("Chinese IBE standard"), sm9.DefaultEncrypterOpts)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error from Encrypt: %s\n", err)
		return
	}
	// Since Encrypt is a randomized function, result will be
	// different each time.
	fmt.Printf("%s\n", hex.EncodeToString(ciphertext))
}


func ExampleEncryptPrivateKey_Decrypt() {
	// real user encrypt private key should be from secret storage.
	kb, _ := hex.DecodeString("038182000494736acd2c8c8796cc4785e938301a139a059d3537b6414140b2d31eecf41683115bae85f5d8bc6c3dbd9e5342979acccf3c2f4f28420b1cb4f8c0b59a19b1587aa5e47570da7600cd760a0cf7beaf71c447f3844753fe74fa7ba92ca7d3b55f27538a62e7f7bfb51dce08704796d94c9d56734f119ea44732b50e31cdeb75c1")
	userKey := new(sm9.EncryptPrivateKey)
	err := userKey.UnmarshalASN1(kb)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error from UnmarshalASN1: %s\n", err)
		return
	}
	uid := []byte("Bob")
	cipherDer, _ := hex.DecodeString("307f020100034200042cb3e90b0977211597652f26ee4abbe275ccb18dd7f431876ab5d40cc2fc563d9417791c75bc8909336a4e6562450836cc863f51002e31ecf0c4aae8d98641070420638ca5bfb35d25cff7cbd684f3ed75f2d919da86a921a2e3e2e2f4cbcf583f240414b7e776811774722a8720752fb1355ce45dc3d0df")
	plaintext, err := userKey.DecryptASN1(uid, cipherDer)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error from Decrypt: %s\n", err)
		return
	}
	fmt.Printf("%s\n", plaintext)
	// Output: Chinese IBE standard
}
```

密文封装结果ASN.1格式请参考参考《GB/T 41389-2022 信息安全技术 SM9密码算法使用规范》。

SM9公钥加密算法支持多种对称加密算法，不像SM2公钥加密算法，只支持XOR。不过由于非XOR对称加密算法有几个需要IV，而规范没有定义，所以会有互操作问题，
* [关于SM9 非XOR加密标准问题](https://github.com/emmansun/gmsm/discussions/112)。
* 《GB/T 41389-2022 信息安全技术 SM9密码算法使用规范》6.1.5 加密数据格式。

## 密钥交换
在这里不详细介绍使用方法，一般只有tls/tlcp才会用到，普通应用通常不会涉及这一块，请参考[API Document](https://godoc.org/github.com/emmansun/gmsm)。

## 性能
参考[SM9实现及优化](https://github.com/emmansun/gmsm/wiki/SM9%E5%AE%9E%E7%8E%B0%E5%8F%8A%E4%BC%98%E5%8C%96)。
