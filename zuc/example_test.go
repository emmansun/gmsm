package zuc_test

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"

	"github.com/emmansun/gmsm/zuc"
)

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
