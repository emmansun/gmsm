# 祖冲之序列密码算法应用指南

## 参考标准
* 《GB/T 33133.1-2016 信息安全技术 祖冲之序列密码算法 第1部分：算法描述》
* 《GB/T 33133.2-2021 信息安全技术 祖冲之序列密码算法 第2部分：保密性算法》
* 《GB/T 33133.3-2021 信息安全技术 祖冲之序列密码算法 第2部分：完整性算法》
* [《祖冲之算法：ZUC-256算法草案(中文)》](https://github.com/guanzhi/GM-Standards/blob/master/%E5%85%AC%E5%BC%80%E6%96%87%E6%A1%A3/%E7%A5%96%E5%86%B2%E4%B9%8B%E7%AE%97%E6%B3%95%EF%BC%9AZUC-256%E7%AE%97%E6%B3%95%E8%8D%89%E6%A1%88(%E4%B8%AD%E6%96%87).pdf)
* 《GM/T 0001.4-2024 祖冲之序列密码算法 第4部分鉴别式加密机制》

您可以从[国家标准全文公开系统](https://openstd.samr.gov.cn/)在线阅读这些标准。

## 保密性算法
保密性算法EEA实现了```cipher.Stream```接口，所以和其它流密码算法使用类似，只是创建方法不同而已。

|  | ZUC-128 | ZUC-256 |  
| :--- | :--- | :--- |
| Key字节数 | 16 | 32 |
| IV字节数 | 16 | 23 |  

```go
func ExampleNewCipher() {
	// Load your secret key from a safe place and reuse it across multiple
	// NewCipher calls. (Obviously don't use this example key for anything
	// real.) If you want to convert a passphrase to a key, use a suitable
	// package like bcrypt or scrypt.
	key, _ := hex.DecodeString("6368616e676520746869732070617373")
	plaintext := []byte("some plaintext")

	const ivSize = zuc.IVSize128
	// The IV needs to be unique, but not secure. Therefore it's common to
	// include it at the beginning of the ciphertext.
	ciphertext := make([]byte, ivSize+len(plaintext))
	iv := ciphertext[:ivSize]
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		panic(err)
	}

	stream, err := zuc.NewCipher(key, iv)
	if err != nil {
		panic(err)
	}
	stream.XORKeyStream(ciphertext[ivSize:], plaintext)

	// It's important to remember that ciphertexts must be authenticated
	// (i.e. by using crypto/hmac) as well as being encrypted in order to
	// be secure.

	// Stream cipher is the same for both encryption and decryption, so we can
	// also decrypt that ciphertext with NewCTR.

	plaintext2 := make([]byte, len(plaintext))
	stream, err = zuc.NewCipher(key, iv)
	if err != nil {
		panic(err)
	}
	stream.XORKeyStream(plaintext2, ciphertext[ivSize:])

	fmt.Printf("%s\n", plaintext2)
	// Output: some plaintext
}

func ExampleNewCipher_zuc256() {
	// Load your secret key from a safe place and reuse it across multiple
	// NewCipher calls. (Obviously don't use this example key for anything
	// real.) If you want to convert a passphrase to a key, use a suitable
	// package like bcrypt or scrypt.
	key, _ := hex.DecodeString("6368616e6765207468697320706173736368616e676520746869732070617373")
	plaintext := []byte("some plaintext")

	const ivSize = zuc.IVSize256
	// The IV needs to be unique, but not secure. Therefore it's common to
	// include it at the beginning of the ciphertext.
	ciphertext := make([]byte, ivSize+len(plaintext))
	iv := ciphertext[:ivSize]
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		panic(err)
	}

	stream, err := zuc.NewCipher(key, iv)
	if err != nil {
		panic(err)
	}
	stream.XORKeyStream(ciphertext[ivSize:], plaintext)

	// It's important to remember that ciphertexts must be authenticated
	// (i.e. by using crypto/hmac) as well as being encrypted in order to
	// be secure.

	// Stream cipher is the same for both encryption and decryption, so we can
	// also decrypt that ciphertext with NewCTR.

	plaintext2 := make([]byte, len(plaintext))
	stream, err = zuc.NewCipher(key, iv)
	if err != nil {
		panic(err)
	}
	stream.XORKeyStream(plaintext2, ciphertext[ivSize:])

	fmt.Printf("%s\n", plaintext2)
	// Output: some plaintext
}
```
### Seekable Stream
完整性算法支持Seekable Stream，也就是随机定位到某点进行处理，内部实现了分桶缓存状态，每个状态的大小大概是88字节，`bucketSize`的大小可以结合要处理的流大小以及内存占用来平衡考虑。同时，`bucketSize`内部会被处理成128字节的倍数，以利于实现。

如果您没有对同一个流反复进行**前进**、**后退**加解密的需求，可以使用`NewCipher`或者`NewEEACipher`方法，避免内部状态缓存。

## 完整性算法
完整性算法实现了```hash.Hash```接口，所以其使用方法和其它哈希算法类似。

|  | ZUC-128 | ZUC-256 |  
| :--- | :--- | :--- |
| Key字节数 | 16 | 32 |
| IV字节数 | 16 | 23 | 
| MAC字节数 | 4 | 4/8/16 | 

```go
func ExampleNewHash() {
	// Load your secret key from a safe place and reuse it across multiple
	// NewCipher calls. (Obviously don't use this example key for anything
	// real.) If you want to convert a passphrase to a key, use a suitable
	// package like bcrypt or scrypt.
	key, _ := hex.DecodeString("6368616e676520746869732070617373")

	// iv should be generated randomly
	iv, _ := hex.DecodeString("6368616e676520746869732070617373")

	h, err := zuc.NewHash(key, iv)
	if err != nil {
		panic(err)
	}
	h.Write([]byte("hello world\n"))
	fmt.Printf("%x", h.Sum(nil))
	// Output: c43cd26a
}

func ExampleNewHash256_tagSize4() {
	// Load your secret key from a safe place and reuse it across multiple
	// NewCipher calls. (Obviously don't use this example key for anything
	// real.) If you want to convert a passphrase to a key, use a suitable
	// package like bcrypt or scrypt.
	key, _ := hex.DecodeString("6368616e6765207468697320706173736368616e676520746869732070617373")

	// iv should be generated randomly
	iv, _ := hex.DecodeString("6368616e6765207468697320706173736368616e676520")

	h, err := zuc.NewHash256(key, iv, 4)
	if err != nil {
		panic(err)
	}
	h.Write([]byte("hello world\n"))
	fmt.Printf("%x", h.Sum(nil))
	// Output: b76f96ed
}

func ExampleNewHash256_tagSize8() {
	// Load your secret key from a safe place and reuse it across multiple
	// NewCipher calls. (Obviously don't use this example key for anything
	// real.) If you want to convert a passphrase to a key, use a suitable
	// package like bcrypt or scrypt.
	key, _ := hex.DecodeString("6368616e6765207468697320706173736368616e676520746869732070617373")

	// iv should be generated randomly
	iv, _ := hex.DecodeString("6368616e6765207468697320706173736368616e676520")

	h, err := zuc.NewHash256(key, iv, 8)
	if err != nil {
		panic(err)
	}
	h.Write([]byte("hello world\n"))
	fmt.Printf("%x", h.Sum(nil))
	// Output: f28aea6c9db3dc69
}

func ExampleNewHash256_tagSize16() {
	// Load your secret key from a safe place and reuse it across multiple
	// NewCipher calls. (Obviously don't use this example key for anything
	// real.) If you want to convert a passphrase to a key, use a suitable
	// package like bcrypt or scrypt.
	key, _ := hex.DecodeString("6368616e6765207468697320706173736368616e676520746869732070617373")

	// iv should be generated randomly
	iv, _ := hex.DecodeString("6368616e6765207468697320706173736368616e676520")

	h, err := zuc.NewHash256(key, iv, 16)
	if err != nil {
		panic(err)
	}
	h.Write([]byte("hello world\n"))
	fmt.Printf("%x", h.Sum(nil))
	// Output: fd8d10ea65b6369cccc07d50b4657d84
}
```

要支持位为单位的话，可以调用```Finish```方法。
```go
func ExampleZUC128Mac_Finish() {
	key := make([]byte, 16)
	iv := make([]byte, 16)
	h, err := zuc.NewHash(key, iv)
	if err != nil {
		panic(err)
	}
	fmt.Printf("%x", h.Finish([]byte{0}, 1))
	// Output: c8a9595e
}

func ExampleZUC128Mac_Finish_mixed() {
	key := []byte{
		0xc9, 0xe6, 0xce, 0xc4, 0x60, 0x7c, 0x72, 0xdb,
		0x00, 0x0a, 0xef, 0xa8, 0x83, 0x85, 0xab, 0x0a,
	}

	// iv should be generated randomly
	iv, _ := hex.DecodeString("a94059da50000000294059da50008000")

	h, err := zuc.NewHash(key, iv)
	if err != nil {
		panic(err)
	}

	in, _ := hex.DecodeString("983b41d47d780c9e1ad11d7eb70391b1de0b35da2dc62f83e7b78d6306ca0ea07e941b7be91348f9fcb170e2217fecd97f9f68adb16e5d7d21e569d280ed775cebde3f4093c53881")
	h.Write(in)
	fmt.Printf("%x", h.Finish([]byte{0}, 1))
	// Output: fae8ff0b
}
```

## 鉴别式加密机制

GM/T 0001.4-2024《祖冲之序列密码算法 第4部分：鉴别式加密机制》定义了两种基于 ZUC 流密码的认证加密模式：**GXM**（第6章）和 **MUR**（第7章）。两者均在 `cipher` 包中实现，通过内部复用 GHASH 函数构造消息认证码。

### ZUC-GXM

GXM（Galois XOR Mode）是一种类 GCM 的认证加密模式，使用单个流密码实例进行加密并借助 GHASH 生成认证标签。

**密钥材料**

| 参数 | 说明 |
| :--- | :--- |
| `k`（流密码密钥） | ZUC 密钥，传入 `zuc.NewCipher` |
| `iv` | ZUC IV，传入 `zuc.NewCipher` |
| `h`（哈希密钥） | 16 字节，独立于流密码密钥 |

**使用步骤**

1. 用 `k`/`iv` 创建 `zuc.NewCipher`，得到流密码实例 `stream`；
2. 用 `stream` 和 `h` 构造 GXM 实例；
3. 调用 `Seal` / `Open`。

> **注意**：同一个 `stream` 实例**不得复用**，因为 GXM 在初始化时会消耗流密码的首个密钥流块来生成标签掩码。

```go
import (
    "encoding/hex"
    gocipher "crypto/cipher"

    "github.com/emmansun/gmsm/cipher"
    "github.com/emmansun/gmsm/zuc"
)

// GM/T 0001.4-2024 附录 C.2 示例
key, _ := hex.DecodeString("edbe06afed8075576aad04afdec91d32")
iv, _  := hex.DecodeString("b3a6db3c870c3e99245e0d1c06b747de")
hkey, _ := hex.DecodeString("6db45e4f9572f4e6fe0d91acda6801d5")
aad, _ := hex.DecodeString("9de18b1fdab0ca9902b9729d492c807ec599d5")

// 加密
stream, err := zuc.NewCipher(key, iv)
if err != nil {
    panic(err)
}
g, err := cipher.NewGXM(stream, hkey)
if err != nil {
    panic(err)
}
ciphertext := g.Seal(nil, plaintext, aad) // ciphertext = 密文 || 16字节标签

// 解密（需要重新创建 stream，不可复用）
stream2, err := zuc.NewCipher(key, iv)
if err != nil {
    panic(err)
}
g2, err := cipher.NewGXM(stream2, hkey)
if err != nil {
    panic(err)
}
plaintext2, err := g2.Open(nil, ciphertext, aad)
if err != nil {
    panic(err) // 标签验证失败
}
```

标签长度默认为 16 字节；如需 8 字节标签，使用 `cipher.NewGXMWithTagSize(stream, hkey, 8)`。

---

### ZUC-MUR

MUR（Misuse-resistant）是一种**抗误用**认证加密模式：即使 IV 被意外重用，也不会像 GCM 那样彻底失去保密性。代价是需要两个独立的流密码密钥（`dataKey` 和 `tagKey`），以及两次流密码调用（合成 IV 派生机制）。

**密钥材料**

| 参数 | 说明 |
| :--- | :--- |
| `h`（哈希密钥） | 16 字节，用于 GHASH |
| `k1`（dataKey） | ZUC 密钥，用于加密 |
| `k2`（tagKey） | ZUC 密钥，用于生成标签 |
| `iv` | 公共 IV，两路流密码均使用（长度需一致） |

**工作原理（Seal）**

1. 对明文和附加数据做 GHASH，结果与 IV 混合，派生出**合成 IV₁**；
2. 用 `(k2, IV₁)` 创建流密码，加密全零块得到 `tag`；
3. 用 `tag XOR iv` 作为 IV₂，用 `(k1, IV₂)` 加密明文；
4. 输出：密文 || 标签。

```go
import (
    _cipher "crypto/cipher"
    "github.com/emmansun/gmsm/cipher"
    "github.com/emmansun/gmsm/zuc"
)

zucCreator := func(key, iv []byte) (_cipher.Stream, error) {
    return zuc.NewCipher(key, iv)
}

iv, _   := hex.DecodeString("bb8b76cfe5f0d9335029008b2a3b2b21")
hkey, _ := hex.DecodeString("ee767d503bb3d5d1b585f57a0418c673")
k1, _  := hex.DecodeString("e4b5c1f8578034ce6424f58c675597ac") // dataKey
k2, _  := hex.DecodeString("608053f6af9efda562d95dc013bea6b5") // tagKey
aad, _ := hex.DecodeString("fcdd4cb97995da30efd957194eac4d2a...")

g, err := cipher.NewMUR(zucCreator, hkey)
if err != nil {
    panic(err)
}

// 加密
ciphertext, err := g.Seal(iv, k1, k2, nil, plaintext, aad)
if err != nil {
    panic(err)
}

// 解密
plaintext2, err := g.Open(iv, k1, k2, nil, ciphertext, aad)
if err != nil {
    panic(err) // 标签验证失败
}
```

`g`（`*mur` 实例）可安全复用：MUR 不在实例内部保存任何每次加密的状态，流密码实例在每次 `Seal`/`Open` 内部按需创建。

标签长度默认 16 字节；如需 8 字节标签，使用 `cipher.NewMURWithTagSize(zucCreator, hkey, 8)`。

---

### GXM 与 MUR 对比

| 属性 | GXM | MUR |
| :--- | :---: | :---: |
| 密钥数量 | 1（流密码）+ 1（哈希） | 2（流密码）+ 1（哈希） |
| 流密码调用次数 | 1 | 2 |
| 实例可复用 | 否（stream 不可复用） | 是（`*mur` 可复用） |
| IV 误用安全 | 否 | 是（合成 IV） |
| 标准来源 | GM/T 0001.4-2024 第6章 | GM/T 0001.4-2024 第7章 |
| 接口风格 | 类似 `cipher.AEAD` | 扩展参数（含双密钥） |

