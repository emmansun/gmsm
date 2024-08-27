# SM4分组密码算法应用指南
## 参考标准
* 《GB/T 32907-2016 信息安全技术 SM4分组密码算法》
* 《GB/T 17964-2021 信息安全技术 分组密码算法的工作模式》

您可以从[国家标准全文公开系统](https://openstd.samr.gov.cn/)在线阅读这些标准。

## 概述
SM4分组密码算法，其地位类似NIST中的AES分组密码算法，密钥长度128位（16字节），分组大小也是128位（16字节）。在本软件库中，SM4的实现与Go语言中的AES实现一致，也实现了```cipher.Block```接口，所以，所有Go语言中实现的工作模式（CBC/GCM/CFB/OFB/CTR），都能与SM4组合使用。

## [工作模式](https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation)
Go语言实现的工作模式，主要有三类：
* 基于分组的工作模式 ```cipher.BlockMode```，譬如CBC。
* 带有关联数据的认证加密工作模式```cipher.AEAD```，譬如GCM。
* 流加密工作模式```cipher.Stream```，譬如CTR、CFB、OFB。

在实际加解密操作中，我们一般不会直接使用```cipher.Block```，必须结合分组密码算法的工作模式使用。除了Go语言自带的工作模式（CBC/GCM/CFB/OFB/CTR），本软件库也实现了下列工作模式：
* ECB - 电码本模式
* BC - 分组链接模式
* HCTR - 带泛杂凑函数的计数器模式
* XTS - 带密文挪用的XEX可调分组密码模式
* OFBNLF - 带非线性函数的输出反馈模式
* CCM - 分组密码链接-消息认证码组合模式

其中，ECB/BC/HCTR/XTS/OFBNLF是《GB/T 17964-2021 信息安全技术 分组密码算法的工作模式》列出的工作模式。BC/OFBNLF模式是商密中的遗留工作模式，**不建议**在新的应用中使用。XTS/HCTR模式适用于对磁盘加密，其中HCTR模式是《GB/T 17964-2021 信息安全技术 分组密码算法的工作模式》最新引入的，HCTR模式最近业界研究比较多，也指出了原论文中的Bugs：On modern processors HCTR [WFW05](https://citeseerx.ist.psu.edu/viewdoc/summary?doi=10.1.1.470.5288) is one of the most efficient constructions for building a tweakable super-pseudorandom permutation. However, a bug in the specification and another in Chakraborty and Nandi’s security proof [CN08](https://www.iacr.org/cryptodb/archive/2008/FSE/paper/15611.pdf) invalidate the claimed security bound.  
不知道这个不足是否会影响到这个工作模式的采用。很奇怪《GB/T 17964-2021 信息安全技术 分组密码算法的工作模式》为何没有纳入GCM工作模式，难道是版权问题？

本软件库引入CCM模式，只是为了有些标准还用到该模式。ECB模式也不建议单独使用。

目前，本软件库的SM4针对ECB/CBC/GCM/XTS工作模式进行了绑定组合性能优化，暂时没有计划使用汇编优化HCTR模式（HCTR模式可以采用和GCM类似的方法进行汇编优化）。

### 使用建议
常用的对称加解密应用场合，推荐优先使用GCM模式，其次CBC模式（一些安全扫描工具，也会把CBC工作模式列为安全性不高的工作模式）。我能想到的GCM模式的缺点是：加解密的相关方不支持GCM模式，或者实现性能不好。


## 填充（padding）
有些分组密码算法的工作模式（譬如实现了```cipher.BlockMode```接口的模式）的输入要求是其长度必须是分组大小的整数倍。《GB/T 17964-2021 信息安全技术 分组密码算法的工作模式》附录C中列出了以下几种填充模式：
* 填充方式 1，对应本软件库的```padding.NewPKCS7Padding```
* 填充方式 2，对应本软件库的```padding.NewISO9797M2Padding```
* 填充方式 3，目前没有实现，它对应ISO/IEC_9797-1 padding method 3

本软件库也实现了ANSI X9.23标准中定义的填充方式```padding.NewANSIX923Padding```，**用的最广的还是填充方式 1：PKCS7填充**。

您如果使用实现了```cipher.BlockMode```接口的分组加密工作模式，那您也必须与相关方协调好填充模式。JAVA库的对称加密算法字符串名就包含了所有信息，譬如**AES/CBC/PKCS7Padding**。

## 密文及其相关参数的传输和存储
如果是自描述的，那肯定有相关标准，定义相关ASN.1结构，并且给分组密码算法、工作模式、填充方式都赋予一个OID。或者如hashicorp vault，一个对称密钥确定了分组密码算法、工作模式、填充方式，最终输出密文是密钥ID和原始密文的组合。

如果是内部服务之间，可能是在应用/服务级别自定义所使用分组密码算法、工作模式、填充方式的标识，作为应用的METADATA，也就是加密用的METADATA和密文分离。

也可能是隐式使用一致的分组密码算法、工作模式、填充方式，也就是代码知道，还有文档知道？

具体使用哪种方式，取决于应用场景。

另外一个就是必须和密文一起存储/传输的参数，譬如，如果使用CBC工作模式，那IV怎么办？如果是GCM模式，那Nonce、Nonce长度、Tag长度怎么办？这通常也有两种方案：
* 使用预定义的ASN.1结构
* 和密文简单拼接：譬如CBC工作模式：前面16字节IV，后面ciphertext；GCM模式（使用默认Tag长度和Nonce长度）：前面12字节Nonce，后面ciphertext。

至于要将二进制转为文本传输、存储，编个码就行：标准base64 / URL base64 / HEX，事先协调、定义好就可以了。这里顺便推荐一下[性能更好的BASE64实现](https://github.com/emmansun/base64)。

## API文档及示例
这里只列出GCM/CBC的例子，其余请参考[API Document](https://godoc.org/github.com/emmansun/gmsm)。

### GCM示例
```go
func Example_encryptGCM() {
	// Load your secret key from a safe place and reuse it across multiple
	// Seal/Open calls. (Obviously don't use this example key for anything
	// real.) If you want to convert a passphrase to a key, use a suitable
	// package like bcrypt or scrypt.
	key, _ := hex.DecodeString("6368616e676520746869732070617373")
	plaintext := []byte("exampleplaintext")

	block, err := sm4.NewCipher(key)
	if err != nil {
		panic(err.Error())
	}

	// Never use more than 2^32 random nonces with a given key because of the risk of a repeat.
	nonce := make([]byte, 12)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		panic(err.Error())
	}

	sm4gcm, err := cipher.NewGCM(block)
	if err != nil {
		panic(err.Error())
	}

	// You can encode the nonce and ciphertext with your own scheme
	ciphertext := sm4gcm.Seal(nil, nonce, plaintext, nil)
	fmt.Printf("%x %x\n", nonce, ciphertext)
}

func Example_decryptGCM() {
	// Load your secret key from a safe place and reuse it across multiple
	// Seal/Open calls. (Obviously don't use this example key for anything
	// real.) If you want to convert a passphrase to a key, use a suitable
	// package like bcrypt or scrypt.
	key, _ := hex.DecodeString("6368616e676520746869732070617373")
	// You can decode the nonce and ciphertext with your encoding scheme
	ciphertext, _ := hex.DecodeString("b7fdece1c6b3dce9cc386e8bc93df0ce496df789166229f14b973b694a4a23c3")
	nonce, _ := hex.DecodeString("07d168e0517656ab7131f495")

	block, err := sm4.NewCipher(key)
	if err != nil {
		panic(err.Error())
	}

	sm4gcm, err := cipher.NewGCM(block)
	if err != nil {
		panic(err.Error())
	}

	plaintext, err := sm4gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		panic(err.Error())
	}

	fmt.Printf("%s\n", plaintext)
	// Output: exampleplaintext
}
```

### CBC示例
```go
func Example_encryptCBC() {
	// Load your secret key from a safe place and reuse it across multiple
	// NewCipher calls. (Obviously don't use this example key for anything
	// real.) If you want to convert a passphrase to a key, use a suitable
	// package like bcrypt or scrypt.
	key, _ := hex.DecodeString("6368616e676520746869732070617373")
	plaintext := []byte("sm4 exampleplaintext")

	block, err := sm4.NewCipher(key)
	if err != nil {
		panic(err)
	}

	// CBC mode works on blocks so plaintexts may need to be padded to the
	// next whole block. For an example of such padding, see
	// https://tools.ietf.org/html/rfc5246#section-6.2.3.2.
	pkcs7 := padding.NewPKCS7Padding(sm4.BlockSize)
	paddedPlainText := pkcs7.Pad(plaintext)

	// The IV needs to be unique, but not secure. Therefore it's common to
	// include it at the beginning of the ciphertext.
	ciphertext := make([]byte, sm4.BlockSize+len(paddedPlainText))
	iv := ciphertext[:sm4.BlockSize]
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		panic(err)
	}

	mode := cipher.NewCBCEncrypter(block, iv)
	mode.CryptBlocks(ciphertext[sm4.BlockSize:], paddedPlainText)

	fmt.Printf("%x\n", ciphertext)
}

func Example_decryptCBC() {
	// Load your secret key from a safe place and reuse it across multiple
	// NewCipher calls. (Obviously don't use this example key for anything
	// real.) If you want to convert a passphrase to a key, use a suitable
	// package like bcrypt or scrypt.
	key, _ := hex.DecodeString("6368616e676520746869732070617373")
	ciphertext, _ := hex.DecodeString("4d5a1486bfda1b34447afd5bb852e77a867cc6b726a8a0e0ef9b2c21fffc3a30b42acf504628f65cb3fba339101c98ff")

	block, err := sm4.NewCipher(key)
	if err != nil {
		panic(err)
	}

	// The IV needs to be unique, but not secure. Therefore it's common to
	// include it at the beginning of the ciphertext.
	if len(ciphertext) < sm4.BlockSize {
		panic("ciphertext too short")
	}
	iv := ciphertext[:sm4.BlockSize]
	ciphertext = ciphertext[sm4.BlockSize:]

	mode := cipher.NewCBCDecrypter(block, iv)

	// CryptBlocks can work in-place if the two arguments are the same.
	mode.CryptBlocks(ciphertext, ciphertext)

	// Unpad plaintext
	pkcs7 := padding.NewPKCS7Padding(sm4.BlockSize)
	ciphertext, err = pkcs7.Unpad(ciphertext)
	if err != nil {
		panic(err)
	}

	fmt.Printf("%s\n", ciphertext)
	// Output: sm4 exampleplaintext
}
```

需要注意一下，```cipher.AEAD```对```dst```参数的要求：

```cipher.AEAD```是**追加**结果，所以如果要重用切片，要注意一下。而且```Seal```的结果要比plaintext长（加上tag），所以只有```cap(plaintext)>=len(plaintext)+tagSize```时才会重用，否则还是会新建一个切片。
```go
// AEAD is a cipher mode providing authenticated encryption with associated
// data. For a description of the methodology, see
// https://en.wikipedia.org/wiki/Authenticated_encryption.
type AEAD interface {
	// NonceSize returns the size of the nonce that must be passed to Seal
	// and Open.
	NonceSize() int

	// Overhead returns the maximum difference between the lengths of a
	// plaintext and its ciphertext.
	Overhead() int

	// Seal encrypts and authenticates plaintext, authenticates the
	// additional data and appends the result to dst, returning the updated
	// slice. The nonce must be NonceSize() bytes long and unique for all
	// time, for a given key.
	//
	// To reuse plaintext's storage for the encrypted output, use plaintext[:0]
	// as dst. Otherwise, the remaining capacity of dst must not overlap plaintext.
	Seal(dst, nonce, plaintext, additionalData []byte) []byte

	// Open decrypts and authenticates ciphertext, authenticates the
	// additional data and, if successful, appends the resulting plaintext
	// to dst, returning the updated slice. The nonce must be NonceSize()
	// bytes long and both it and the additional data must match the
	// value passed to Seal.
	//
	// To reuse ciphertext's storage for the decrypted output, use ciphertext[:0]
	// as dst. Otherwise, the remaining capacity of dst must not overlap plaintext.
	//
	// Even if the function fails, the contents of dst, up to its capacity,
	// may be overwritten.
	Open(dst, nonce, ciphertext, additionalData []byte) ([]byte, error)
}
```
而```cipher.BlockMode```和```cipher.Stream```的话，则是直接覆盖。

## 性能
SM4分组密码算法的软件高效实现，不算CPU指令支持的话，已知有如下几种方法：
* S盒和L转换预计算，本软件库纯Go语言实现采用该方法
* SIMD并行处理：并行查表
* SIMD并行处理：借助CPU的AES指令，本软件库采用该方法
* SIMD并行处理：位切片(bitslicing)，[参考实现](https://github.com/emmansun/sm4bs)

当然，这些与有CPU指令支持的AES算法相比，性能差距依然偏大，要是工作模式不支持并行，差距就更巨大了。

### 混合方式
从**v0.25.0**开始，AMD64/ARM64 支持AES-NI的CPU架构下，**默认会使用混合方式**，即```cipher.Block```的方法会用纯Go语言实现，而对于可以并行的加解密模式，则还是会尽量采用AES-NI和SIMD并行处理。您可以通过环境变量```FORCE_SM4BLOCK_AESNI=1```来强制都使用AES-NI实现（和v0.25.0之前版本的行为一样）。请参考[SM4: 单block的性能问题](https://github.com/emmansun/gmsm/discussions/172)。

**注意**：目前的纯Golang SM4实现（查表实现）是以可变时间运行的！

## 与KMS集成
可能您会说，如果我在KMS中创建了一个SM4对称密钥，就不需要本地加解密了，这话很对，不过有种场景会用到：  
* 在KMS中只创建非对称密钥（KEK）；
* 对称加解密在本地进行；
* 对称加密密钥，或者称为数据密钥(DEK/CEK)，可以在本地通过安全伪随机数函数生成，也可以通过KMS的Data Key API生成（如果有这类API的话），用Data Key API的话，会有DEK/CEK明文传输问题，毕竟KMS需要把DEK/CEK的密文/明文同时返回。

这种加密方案有什么优点呢？  
* KMS API通常都会限流，譬如200次/秒，通过把对称加解密放在本地进行，可以有效减少KMS交互。
* 减少网络带宽占用。
* 避免明文数据的网络传输。

当然，前提是用于本地对称加解密的SM4分组密码算法和选用的工作模式性能可以满足需求。
