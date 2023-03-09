package pkcs7

import (
	"bytes"
	"crypto/x509"
	"encoding/pem"
	"os"
	"testing"

	"github.com/emmansun/gmsm/pkcs"
	"github.com/emmansun/gmsm/smx509"
)

func TestEncrypt(t *testing.T) {
	ciphers := []pkcs.Cipher{
		pkcs.DESCBC,
		pkcs.TripleDESCBC,
		pkcs.SM4CBC,
		pkcs.SM4GCM,
		pkcs.AES128CBC,
		pkcs.AES192CBC,
		pkcs.AES256CBC,
		pkcs.AES128GCM,
		pkcs.AES192GCM,
		pkcs.AES256GCM,
	}
	sigalgs := []x509.SignatureAlgorithm{
		x509.SHA1WithRSA,
		x509.SHA256WithRSA,
		x509.SHA512WithRSA,
		smx509.SM2WithSM3,
	}
	for _, cipher := range ciphers {
		for _, sigalg := range sigalgs {
			plaintext := []byte("Hello Secret World!")
			cert, err := createTestCertificate(sigalg)
			if err != nil {
				t.Fatal(err)
			}
			encrypted, err := Encrypt(cipher, plaintext, []*smx509.Certificate{cert.Certificate})
			if err != nil {
				t.Fatal(err)
			}
			p7, err := Parse(encrypted)
			if err != nil {
				t.Fatalf("cannot Parse encrypted result: %s", err)
			}
			result, err := p7.Decrypt(cert.Certificate, *cert.PrivateKey)
			if err != nil {
				t.Fatalf("cannot Decrypt encrypted result: %s", err)
			}
			if !bytes.Equal(plaintext, result) {
				t.Errorf("encrypted data does not match plaintext:\n\tExpected: %s\n\tActual: %s", plaintext, result)
			}
		}
	}
}

func TestEncryptSM(t *testing.T) {
	ciphers := []pkcs.Cipher{
		pkcs.SM4CBC,
		pkcs.SM4GCM,
	}
	sigalgs := []x509.SignatureAlgorithm{
		smx509.SM2WithSM3,
	}
	for _, cipher := range ciphers {
		for _, sigalg := range sigalgs {
			plaintext := []byte("Hello Secret World!")
			cert, err := createTestCertificate(sigalg)
			if err != nil {
				t.Fatal(err)
			}
			encrypted, err := EncryptSM(cipher, plaintext, []*smx509.Certificate{cert.Certificate})
			if err != nil {
				t.Fatal(err)
			}
			pem.Encode(os.Stdout, &pem.Block{Type: "PKCS7", Bytes: encrypted})
			p7, err := Parse(encrypted)
			if err != nil {
				t.Fatalf("cannot Parse encrypted result: %s", err)
			}
			result, err := p7.Decrypt(cert.Certificate, *cert.PrivateKey)
			if err != nil {
				t.Fatalf("cannot Decrypt encrypted result: %s", err)
			}
			if !bytes.Equal(plaintext, result) {
				t.Errorf("encrypted data does not match plaintext:\n\tExpected: %s\n\tActual: %s", plaintext, result)
			}
		}
	}
}

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
