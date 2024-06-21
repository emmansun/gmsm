package pkcs7

import (
	"bytes"
	"testing"

	"github.com/emmansun/gmsm/pkcs"
)

func TestEncryptUsingPSK(t *testing.T) {
	ciphers := []pkcs.Cipher{
		pkcs.DESCBC,
		pkcs.SM4GCM,
		pkcs.AES128GCM,
	}

	for _, cipher := range ciphers {
		plaintext := []byte("Hello Secret World!")
		var key []byte

		switch cipher.KeySize() {
		case 8:
			key = []byte("64BitKey")
		case 16:
			key = []byte("128BitKey4AESGCM")
		}
		ciphertext, err := EncryptUsingPSK(cipher, plaintext, key)
		if err != nil {
			t.Fatal(err)
		}

		p7, _ := Parse(ciphertext)
		result, err := p7.DecryptUsingPSK(key)
		if err != nil {
			t.Fatalf("cannot Decrypt encrypted result: %s", err)
		}
		if !bytes.Equal(plaintext, result) {
			t.Errorf("encrypted data does not match plaintext:\n\tExpected: %s\n\tActual: %s", plaintext, result)
		}
	}
}

func TestEncryptSMUsingPSK(t *testing.T) {
	ciphers := []pkcs.Cipher{
		pkcs.DESCBC,
		pkcs.SM4GCM,
		pkcs.AES128GCM,
	}

	for _, cipher := range ciphers {
		plaintext := []byte("Hello Secret World!")
		var key []byte

		switch cipher.KeySize() {
		case 8:
			key = []byte("64BitKey")
		case 16:
			key = []byte("128BitKey4AESGCM")
		}
		ciphertext, err := EncryptSMUsingPSK(cipher, plaintext, key)
		if err != nil {
			t.Fatal(err)
		}

		p7, _ := Parse(ciphertext)
		result, err := p7.DecryptUsingPSK(key)
		if err != nil {
			t.Fatalf("cannot Decrypt encrypted result: %s", err)
		}
		if !bytes.Equal(plaintext, result) {
			t.Errorf("encrypted data does not match plaintext:\n\tExpected: %s\n\tActual: %s", plaintext, result)
		}
	}
}
