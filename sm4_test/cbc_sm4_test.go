package sm4_test

import (
	"bytes"
	"crypto/cipher"
	"encoding/hex"
	"errors"
	"fmt"
	"testing"

	"github.com/emmansun/gmsm/sm4"
)

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

var cbcSM4Tests = []struct {
	name string
	key  []byte
	iv   []byte
	in   []byte
	out  []byte
}{
	{
		"from internet",
		[]byte("0123456789ABCDEF"),
		[]byte("0123456789ABCDEF"),
		[]byte("Hello World"),
		[]byte{0x0a, 0x67, 0x06, 0x2f, 0x0c, 0xd2, 0xdc, 0xe2, 0x6a, 0x7b, 0x97, 0x8e, 0xbf, 0x21, 0x34, 0xf9},
	},
	{
		"A.1",
		[]byte{0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10},
		[]byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
		[]byte{0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10},
		[]byte{
			0x68, 0x1e, 0xdf, 0x34, 0xd2, 0x06, 0x96, 0x5e, 0x86, 0xb3, 0xe9, 0x4f, 0x53, 0x6e, 0x42, 0x46,
			0x67, 0x7d, 0x30, 0x7e, 0x84, 0x4d, 0x7a, 0xa2, 0x45, 0x79, 0xd5, 0x56, 0x49, 0x0d, 0xc7, 0xaa},
	},
}

func TestCBCEncrypterSM4(t *testing.T) {
	for _, test := range cbcSM4Tests {
		c, err := sm4.NewCipher(test.key)
		if err != nil {
			t.Errorf("%s: NewCipher(%d bytes) = %s", test.name, len(test.key), err)
			continue
		}

		encrypter := cipher.NewCBCEncrypter(c, test.iv)

		plainText := paddingPKCS7(test.in, sm4.BlockSize)
		data := make([]byte, len(plainText))
		copy(data, plainText)

		encrypter.CryptBlocks(data, data)
		if !bytes.Equal(test.out, data) {
			t.Errorf("%s: CBCEncrypter\nhave %s\nwant %x", test.name, hex.EncodeToString(data), test.out)
		}
	}
}

func TestCBCDecrypterSM4(t *testing.T) {
	for _, test := range cbcSM4Tests {
		c, err := sm4.NewCipher(test.key)
		if err != nil {
			t.Errorf("%s: NewCipher(%d bytes) = %s", test.name, len(test.key), err)
			continue
		}

		decrypter := cipher.NewCBCDecrypter(c, test.iv)

		data := make([]byte, len(test.out))
		copy(data, test.out)

		decrypter.CryptBlocks(data, data)
		data, err = unpaddingPKCS7(data, sm4.BlockSize)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(test.in, data) {
			t.Errorf("%s: CBCDecrypter\nhave %x\nwant %x", test.name, data, test.in)
		}
	}
}
