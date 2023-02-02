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
