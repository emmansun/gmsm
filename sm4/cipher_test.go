package sm4

import (
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"reflect"
	"testing"
)

func Test_sample1(t *testing.T) {
	src := []byte{0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10}
	expected := []byte{0x68, 0x1e, 0xdf, 0x34, 0xd2, 0x06, 0x96, 0x5e, 0x86, 0xb3, 0xe9, 0x4f, 0x53, 0x6e, 0x42, 0x46}
	c, err := NewCipher(src)
	if err != nil {
		t.Fatal(err)
	}
	dst := make([]byte, 16)
	c.Encrypt(dst, src)
	if !reflect.DeepEqual(dst, expected) {
		t.Fatalf("expected=%v, result=%v\n", expected, dst)
	}
	c.Decrypt(dst, expected)
	if !reflect.DeepEqual(dst, src) {
		t.Fatalf("expected=%v, result=%v\n", src, dst)
	}
}

func Test_sample2(t *testing.T) {
	src := []byte{0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10}
	expected := []byte{0x59, 0x52, 0x98, 0xc7, 0xc6, 0xfd, 0x27, 0x1f, 0x04, 0x02, 0xf8, 0x04, 0xc3, 0x3d, 0x3f, 0x66}
	c, err := NewCipher(src)
	if err != nil {
		t.Fatal(err)
	}
	dst := make([]byte, 16)
	copy(dst, src)

	for i := 0; i < 1000000; i++ {
		c.Encrypt(dst, dst)
	}
	if !reflect.DeepEqual(dst, expected) {
		t.Fatalf("expected=%v, result=%v\n", expected, dst)
	}
}

func paddingPKCS7(buf []byte, blockSize int) []byte {
	bufLen := len(buf)
	padLen := blockSize - bufLen%blockSize
	padded := make([]byte, bufLen+padLen)
	copy(padded, buf)
	for i := 0; i < padLen; i++ {
		padded[bufLen+i] = byte(padLen)
	}
	return padded
}

func unpaddingPKCS7(padded []byte, size int) ([]byte, error) {
	if len(padded)%size != 0 {
		return nil, errors.New("pkcs7: Padded value wasn't in correct size")
	}
	paddedByte := int(padded[len(padded)-1])
	if (paddedByte > size) || (paddedByte < 1) {
		return nil, fmt.Errorf("Invalid decrypted text, no padding")
	}
	bufLen := len(padded) - paddedByte
	buf := make([]byte, bufLen)
	copy(buf, padded[:bufLen])
	return buf, nil
}

func Test_sm4withcbc_less(t *testing.T) {
	src := []byte("emmansun")
	key := []byte("passwordpassword")
	block, err := NewCipher(key)
	if err != nil {
		t.Fatal(err)
	}
	plainText := paddingPKCS7(src, BlockSize)
	cipherText := make([]byte, BlockSize+len(plainText))
	iv := cipherText[:BlockSize]
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		t.Fatal(err)
	}

	mode := cipher.NewCBCEncrypter(block, iv)
	mode.CryptBlocks(cipherText[BlockSize:], plainText)

	iv = cipherText[:BlockSize]
	cipherText = cipherText[BlockSize:]
	mode = cipher.NewCBCDecrypter(block, iv)
	mode.CryptBlocks(cipherText, cipherText)
	result, err := unpaddingPKCS7(cipherText, BlockSize)
	if err != nil {
		t.Fatal(err)
	}
	if string(result) != string(src) {
		t.Fatalf("result=%s, expected=%s\n", string(result), string(src))
	}
}
