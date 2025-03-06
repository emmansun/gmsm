# 祖冲之序列密码算法应用指南

## 参考标准
* 《GB/T 33133.1-2016 信息安全技术 祖冲之序列密码算法 第1部分：算法描述》
* 《GB/T 33133.2-2021 信息安全技术 祖冲之序列密码算法 第2部分：保密性算法》
* 《GB/T 33133.3-2021 信息安全技术 祖冲之序列密码算法 第2部分：完整性算法》
* [《祖冲之算法：ZUC-256算法草案(中文)》](https://github.com/guanzhi/GM-Standards/blob/master/%E5%85%AC%E5%BC%80%E6%96%87%E6%A1%A3/%E7%A5%96%E5%86%B2%E4%B9%8B%E7%AE%97%E6%B3%95%EF%BC%9AZUC-256%E7%AE%97%E6%B3%95%E8%8D%89%E6%A1%88(%E4%B8%AD%E6%96%87).pdf)

您可以从[国家标准全文公开系统](https://openstd.samr.gov.cn/)在线阅读这些标准。

## 保密性算法
保密性算法EEA实现了`cipher.Stream`接口，所以和其它流密码算法使用类似，只是创建方法不同而已。

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

## 完整性算法
完整性算法实现了`hash.Hash`接口，所以其使用方法和其它哈希算法类似。

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

要支持位为单位的话，可以调用`Finish`方法。
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
