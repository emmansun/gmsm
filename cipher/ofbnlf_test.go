package cipher_test

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"io"
	"testing"

	"github.com/emmansun/gmsm/cipher"
	"github.com/emmansun/gmsm/sm4"
)

var ofbnlfSM4TestVectors = []struct {
	key        string
	iv         string
	plaintext  string
	ciphertext string
}{
	{
		"2B7E151628AED2A6ABF7158809CF4F3C",
		"000102030405060708090A0B0C0D0E0F",
		"6BC1BEE22E409F96E93D7E117393172AAE2D8A571E03AC9C9EB76FAC45AF8E5130C81C46A35CE411E5FBC1191A0A52EFF69F2445DF4F9B17AD2B417BE66C3710",
		"00A5B5C9E645557C20CE7F267736F308A18037828850B9D78883CA622851F86CB7CAEFDFB6D4CABA6AE2D2FCE369CEB31001DD71FDDA9341F8D221CB720FF27B",
	},
}

func TestOFBNLF(t *testing.T) {
	for i, test := range ofbnlfSM4TestVectors {
		key, _ := hex.DecodeString(test.key)
		iv, _ := hex.DecodeString(test.iv)
		plaintext, _ := hex.DecodeString(test.plaintext)
		ciphertext, _ := hex.DecodeString(test.ciphertext)
		got := make([]byte, len(plaintext))
		encrypter, err := cipher.NewOFBNLFEncrypter(sm4.NewCipher, key, iv)
		if err != nil {
			t.Fatal(err)
		}
		encrypter.CryptBlocks(got, plaintext)
		if !bytes.Equal(got, ciphertext) {
			t.Fatalf("%v case encrypt failed, got %x\n", i+1, got)
		}

		decrypter, err := cipher.NewOFBNLFDecrypter(sm4.NewCipher, key, iv)
		if err != nil {
			t.Fatal(err)
		}
		decrypter.CryptBlocks(got, ciphertext)
		if !bytes.Equal(got, plaintext) {
			t.Fatalf("%v case decrypt failed, got %x\n", i+1, got)
		}
	}
}

func TestSM4OFBNLFRandom(t *testing.T) {
	key, _ := hex.DecodeString(ofbnlfSM4TestVectors[0].key)
	iv := []byte("0123456789ABCDEF")
	encrypter, _ := cipher.NewOFBNLFEncrypter(sm4.NewCipher, key, iv)
	decrypter, _ := cipher.NewOFBNLFDecrypter(sm4.NewCipher, key, iv)
	for i := 1; i <= 50; i++ {
		plaintext := make([]byte, i*16)
		ciphertext := make([]byte, i*16)
		got := make([]byte, i*16)
		io.ReadFull(rand.Reader, plaintext)
		encrypter.CryptBlocks(ciphertext, plaintext)
		decrypter.CryptBlocks(got, ciphertext)
		if !bytes.Equal(got, plaintext) {
			t.Errorf("test %v blocks failed", i)
		}
	}
}
