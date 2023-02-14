package sm9

import (
	"crypto/rand"
	"testing"
)

func TestInvalidKeySize(t *testing.T) {
	encOpts := []EncrypterOpts{
		SM4ECBEncrypterOpts, SM4CBCEncrypterOpts, SM4CFBEncrypterOpts, SM4OFBEncrypterOpts,
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
	encOpts := []EncrypterOpts{
		SM4CBCEncrypterOpts, SM4CFBEncrypterOpts, SM4OFBEncrypterOpts,
	}
	for _, opts := range encOpts {
		_, err := opts.Decrypt([]byte("1234567890123450"), []byte("ciphertext"))
		if err.Error() != "sm9: decryption error" {
			t.Fatalf("not expected error: %v\n", err.Error())
		}
	}
}

func TestEmptyCiphertext(t *testing.T) {
	encOpts := []EncrypterOpts{
		SM4ECBEncrypterOpts, DefaultEncrypterOpts,
	}
	for _, opts := range encOpts {
		_, err := opts.Decrypt([]byte("1234567890123450"), nil)
		if err.Error() != "sm9: decryption error" {
			t.Fatalf("not expected error: %v\n", err.Error())
		}
	}
}
