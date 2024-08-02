package sm9_test

import (
	"bytes"
	"crypto/aes"
	"crypto/rand"
	"encoding/hex"
	"testing"

	"github.com/emmansun/gmsm/padding"
	"github.com/emmansun/gmsm/sm9"
)

func TestInvalidKeySize(t *testing.T) {
	encOpts := []sm9.EncrypterOpts{
		sm9.SM4ECBEncrypterOpts, sm9.SM4CBCEncrypterOpts, sm9.SM4CFBEncrypterOpts, sm9.SM4OFBEncrypterOpts,
	}
	for _, opts := range encOpts {
		_, err := opts.Encrypt(rand.Reader, []byte("123456789012345"), []byte("plaintext"))
		if err.Error() != "sm4: invalid key size 15" {
			t.Fatalf("not expected error: %v\n", err.Error())
		}
		_, err = opts.Decrypt([]byte("123456789012345"), []byte("ciphertext"))
		if err.Error() != "sm4: invalid key size 15" {
			t.Fatalf("not expected error: %v\n", err.Error())
		}
	}
}

func TestInvalidCiphertextSize(t *testing.T) {
	encOpts := []sm9.EncrypterOpts{
		sm9.SM4CBCEncrypterOpts, sm9.SM4CFBEncrypterOpts, sm9.SM4OFBEncrypterOpts,
	}
	for _, opts := range encOpts {
		_, err := opts.Decrypt([]byte("1234567890123450"), []byte("ciphertext"))
		if err.Error() != "sm9: decryption error" {
			t.Fatalf("not expected error: %v\n", err.Error())
		}
	}
}

func TestEmptyCiphertext(t *testing.T) {
	encOpts := []sm9.EncrypterOpts{
		sm9.SM4ECBEncrypterOpts, sm9.DefaultEncrypterOpts,
	}
	for _, opts := range encOpts {
		_, err := opts.Decrypt([]byte("1234567890123450"), nil)
		if err.Error() != "sm9: decryption error" {
			t.Fatalf("not expected error: %v\n", err.Error())
		}
	}
}

func TestAESEncryption(t *testing.T) {
	key, _ := hex.DecodeString("6368616e6765207468697320706173736368616e676520746869732070617373")
	plaintext := []byte("Chinese IBE standard")
	aescbc := sm9.NewCBCEncrypterOpts(padding.NewPKCS7Padding(aes.BlockSize), aes.NewCipher, 32)

	ciphertext, err := aescbc.Encrypt(rand.Reader, key, plaintext)
	if err != nil {
		t.Fatal(err)
	}
	result, err := aescbc.Decrypt(key, ciphertext)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(plaintext, result) {
		t.Fatalf("no same")
	}
}
