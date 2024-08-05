package cipher_test

import (
	"bytes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/hex"
	"testing"

	"github.com/emmansun/gmsm/internal/cryptotest"
	"github.com/emmansun/gmsm/sm4"
)

var cfbTests = []struct {
	key, iv, plaintext, ciphertext string
}{
	{
		"2b7e151628aed2a6abf7158809cf4f3c",
		"000102030405060708090a0b0c0d0e0f",
		"6bc1bee22e409f96e93d7e117393172a",
		"bc710d762d070b26361da82b54565e46",
	},
	{
		"2b7e151628aed2a6abf7158809cf4f3c",
		"3B3FD92EB72DAD20333449F8E83CFB4A",
		"ae2d8a571e03ac9c9eb76fac45af8e51",
		"945fc8a8241b340d496be6b772d04ee3",
	},
	{
		"2b7e151628aed2a6abf7158809cf4f3c",
		"C8A64537A0B3A93FCDE3CDAD9F1CE58B",
		"30c81c46a35ce411e5fbc1191a0a52ef",
		"ebe17f4c9b41ebe026d99ccdbb1e1e0d",
	},
	{
		"2b7e151628aed2a6abf7158809cf4f3c",
		"26751F67A3CBB140B1808CF187A4F4DF",
		"f69f2445df4f9b17ad2b417be66c3710",
		"422994eb51eb089f1def710f07324be5",
	},
}

func TestCFBVectors(t *testing.T) {
	for i, test := range cfbTests {
		key, err := hex.DecodeString(test.key)
		if err != nil {
			t.Fatal(err)
		}
		iv, err := hex.DecodeString(test.iv)
		if err != nil {
			t.Fatal(err)
		}
		plaintext, err := hex.DecodeString(test.plaintext)
		if err != nil {
			t.Fatal(err)
		}
		expected, err := hex.DecodeString(test.ciphertext)
		if err != nil {
			t.Fatal(err)
		}

		block, err := sm4.NewCipher(key)
		if err != nil {
			t.Fatal(err)
		}

		ciphertext := make([]byte, len(plaintext))
		cfb := cipher.NewCFBEncrypter(block, iv)
		cfb.XORKeyStream(ciphertext, plaintext)

		if !bytes.Equal(ciphertext, expected) {
			t.Errorf("#%d: wrong output: got %x, expected %x", i, ciphertext, expected)
		}

		cfbdec := cipher.NewCFBDecrypter(block, iv)
		plaintextCopy := make([]byte, len(ciphertext))
		cfbdec.XORKeyStream(plaintextCopy, ciphertext)

		if !bytes.Equal(plaintextCopy, plaintext) {
			t.Errorf("#%d: wrong plaintext: got %x, expected %x", i, plaintextCopy, plaintext)
		}
	}
}

func TestCFBInverse(t *testing.T) {
	block, err := sm4.NewCipher([]byte{0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c})
	if err != nil {
		t.Error(err)
		return
	}

	plaintext := []byte("this is the plaintext. this is the plaintext.")
	iv := make([]byte, block.BlockSize())
	rand.Reader.Read(iv)
	cfb := cipher.NewCFBEncrypter(block, iv)
	ciphertext := make([]byte, len(plaintext))
	copy(ciphertext, plaintext)
	cfb.XORKeyStream(ciphertext, ciphertext)

	cfbdec := cipher.NewCFBDecrypter(block, iv)
	plaintextCopy := make([]byte, len(plaintext))
	copy(plaintextCopy, ciphertext)
	cfbdec.XORKeyStream(plaintextCopy, plaintextCopy)

	if !bytes.Equal(plaintextCopy, plaintext) {
		t.Errorf("got: %x, want: %x", plaintextCopy, plaintext)
	}
}

func TestCFBStream(t *testing.T) {
	t.Run("SM4", func(t *testing.T) {
		rng := newRandReader(t)

		key := make([]byte, 16)
		rng.Read(key)

		block, err := sm4.NewCipher(key)
		if err != nil {
			panic(err)
		}

		t.Run("Encrypter", func(t *testing.T) {
			cryptotest.TestStreamFromBlock(t, block, cipher.NewCFBEncrypter)
		})
		t.Run("Decrypter", func(t *testing.T) {
			cryptotest.TestStreamFromBlock(t, block, cipher.NewCFBDecrypter)
		})
	})
}
