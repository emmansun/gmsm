package sm4_test

import (
	"bytes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"os"

	smcipher "github.com/emmansun/gmsm/cipher"
	"github.com/emmansun/gmsm/padding"
	"github.com/emmansun/gmsm/sm4"
)

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

func Example_encryptCCM() {
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

	sm4ccm, err := smcipher.NewCCM(block)
	if err != nil {
		panic(err.Error())
	}

	// You can encode the nonce and ciphertext with your own scheme
	ciphertext := sm4ccm.Seal(nil, nonce, plaintext, nil)
	fmt.Printf("%x %x\n", nonce, ciphertext)
}

func Example_decryptCCM() {
	// Load your secret key from a safe place and reuse it across multiple
	// Seal/Open calls. (Obviously don't use this example key for anything
	// real.) If you want to convert a passphrase to a key, use a suitable
	// package like bcrypt or scrypt.
	key, _ := hex.DecodeString("6368616e676520746869732070617373")
	// You can decode the nonce and ciphertext with your encoding scheme
	ciphertext, _ := hex.DecodeString("aa5da19754e98c3a39787e8f0f8f73808b38ba31c9196772125e737f8d636483")
	nonce, _ := hex.DecodeString("8f227cf05ad8b5c2902844e4")

	block, err := sm4.NewCipher(key)
	if err != nil {
		panic(err.Error())
	}

	sm4ccm, err := smcipher.NewCCM(block)
	if err != nil {
		panic(err.Error())
	}

	plaintext, err := sm4ccm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		panic(err.Error())
	}

	fmt.Printf("%s\n", plaintext)
	// Output: exampleplaintext
}

func Example_encryptCFB() {
	// Load your secret key from a safe place and reuse it across multiple
	// NewCipher calls. (Obviously don't use this example key for anything
	// real.) If you want to convert a passphrase to a key, use a suitable
	// package like bcrypt or scrypt.
	key, _ := hex.DecodeString("6368616e676520746869732070617373")
	plaintext := []byte("some plaintext")

	block, err := sm4.NewCipher(key)
	if err != nil {
		panic(err)
	}

	// The IV needs to be unique, but not secure. Therefore it's common to
	// include it at the beginning of the ciphertext.
	ciphertext := make([]byte, sm4.BlockSize+len(plaintext))
	iv := ciphertext[:sm4.BlockSize]
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		panic(err)
	}

	stream := cipher.NewCFBEncrypter(block, iv)
	stream.XORKeyStream(ciphertext[sm4.BlockSize:], plaintext)

	// It's important to remember that ciphertexts must be authenticated
	// (i.e. by using crypto/hmac) as well as being encrypted in order to
	// be secure.
	fmt.Printf("%x\n", ciphertext)
}

func Example_decryptCFB() {
	// Load your secret key from a safe place and reuse it across multiple
	// NewCipher calls. (Obviously don't use this example key for anything
	// real.) If you want to convert a passphrase to a key, use a suitable
	// package like bcrypt or scrypt.
	key, _ := hex.DecodeString("6368616e676520746869732070617373")
	ciphertext, _ := hex.DecodeString("37386876330ac7a6fa9d22d5b5dba22a779e3ed0e88307121a9808e65894")

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

	stream := cipher.NewCFBDecrypter(block, iv)

	// XORKeyStream can work in-place if the two arguments are the same.
	stream.XORKeyStream(ciphertext, ciphertext)
	fmt.Printf("%s", ciphertext)
	// Output: some plaintext
}

func Example_modeCTR() {
	// Load your secret key from a safe place and reuse it across multiple
	// NewCipher calls. (Obviously don't use this example key for anything
	// real.) If you want to convert a passphrase to a key, use a suitable
	// package like bcrypt or scrypt.
	key, _ := hex.DecodeString("6368616e676520746869732070617373")
	plaintext := []byte("some plaintext")

	block, err := sm4.NewCipher(key)
	if err != nil {
		panic(err)
	}

	// The IV needs to be unique, but not secure. Therefore it's common to
	// include it at the beginning of the ciphertext.
	ciphertext := make([]byte, sm4.BlockSize+len(plaintext))
	iv := ciphertext[:sm4.BlockSize]
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		panic(err)
	}

	stream := cipher.NewCTR(block, iv)
	stream.XORKeyStream(ciphertext[sm4.BlockSize:], plaintext)

	// It's important to remember that ciphertexts must be authenticated
	// (i.e. by using crypto/hmac) as well as being encrypted in order to
	// be secure.

	// CTR mode is the same for both encryption and decryption, so we can
	// also decrypt that ciphertext with NewCTR.

	plaintext2 := make([]byte, len(plaintext))
	stream = cipher.NewCTR(block, iv)
	stream.XORKeyStream(plaintext2, ciphertext[sm4.BlockSize:])

	fmt.Printf("%s\n", plaintext2)
	// Output: some plaintext
}

func Example_modeOFB() {
	// Load your secret key from a safe place and reuse it across multiple
	// NewCipher calls. (Obviously don't use this example key for anything
	// real.) If you want to convert a passphrase to a key, use a suitable
	// package like bcrypt or scrypt.
	key, _ := hex.DecodeString("6368616e676520746869732070617373")
	plaintext := []byte("some plaintext")

	block, err := sm4.NewCipher(key)
	if err != nil {
		panic(err)
	}

	// The IV needs to be unique, but not secure. Therefore it's common to
	// include it at the beginning of the ciphertext.
	ciphertext := make([]byte, sm4.BlockSize+len(plaintext))
	iv := ciphertext[:sm4.BlockSize]
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		panic(err)
	}

	stream := cipher.NewOFB(block, iv)
	stream.XORKeyStream(ciphertext[sm4.BlockSize:], plaintext)

	// It's important to remember that ciphertexts must be authenticated
	// (i.e. by using crypto/hmac) as well as being encrypted in order to
	// be secure.

	// OFB mode is the same for both encryption and decryption, so we can
	// also decrypt that ciphertext with NewOFB.

	plaintext2 := make([]byte, len(plaintext))
	stream = cipher.NewOFB(block, iv)
	stream.XORKeyStream(plaintext2, ciphertext[sm4.BlockSize:])

	fmt.Printf("%s\n", plaintext2)
	// Output: some plaintext
}

func Example_streamReader() {
	// Load your secret key from a safe place and reuse it across multiple
	// NewCipher calls. (Obviously don't use this example key for anything
	// real.) If you want to convert a passphrase to a key, use a suitable
	// package like bcrypt or scrypt.
	key, _ := hex.DecodeString("6368616e676520746869732070617373")

	encrypted, _ := hex.DecodeString("38d03b4b50b6154e7437150b93fb0ef0")
	bReader := bytes.NewReader(encrypted)

	block, err := sm4.NewCipher(key)
	if err != nil {
		panic(err)
	}

	// If the key is unique for each ciphertext, then it's ok to use a zero
	// IV.
	var iv [sm4.BlockSize]byte
	stream := cipher.NewOFB(block, iv[:])

	reader := &cipher.StreamReader{S: stream, R: bReader}
	// Copy the input to the output stream, decrypting as we go.
	if _, err := io.Copy(os.Stdout, reader); err != nil {
		panic(err)
	}

	// Note that this example is simplistic in that it omits any
	// authentication of the encrypted data. If you were actually to use
	// StreamReader in this manner, an attacker could flip arbitrary bits in
	// the output.

	// Output: some secret text
}

func Example_streamWriter() {
	// Load your secret key from a safe place and reuse it across multiple
	// NewCipher calls. (Obviously don't use this example key for anything
	// real.) If you want to convert a passphrase to a key, use a suitable
	// package like bcrypt or scrypt.
	key, _ := hex.DecodeString("6368616e676520746869732070617373")

	bReader := bytes.NewReader([]byte("some secret text"))

	block, err := sm4.NewCipher(key)
	if err != nil {
		panic(err)
	}

	// If the key is unique for each ciphertext, then it's ok to use a zero
	// IV.
	var iv [sm4.BlockSize]byte
	stream := cipher.NewOFB(block, iv[:])

	var out bytes.Buffer

	writer := &cipher.StreamWriter{S: stream, W: &out}
	// Copy the input to the output buffer, encrypting as we go.
	if _, err := io.Copy(writer, bReader); err != nil {
		panic(err)
	}

	// Note that this example is simplistic in that it omits any
	// authentication of the encrypted data. If you were actually to use
	// StreamReader in this manner, an attacker could flip arbitrary bits in
	// the decrypted result.

	fmt.Printf("%x\n", out.Bytes())
	// Output: 38d03b4b50b6154e7437150b93fb0ef0
}
