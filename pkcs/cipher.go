// Package pkcs implements ciphers used by PKCS#7 & PKCS#8.
package pkcs

import (
	"crypto/cipher"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"fmt"
	"io"

	smcipher "github.com/emmansun/gmsm/cipher"
	"github.com/emmansun/gmsm/padding"
)

// Cipher represents a cipher for encrypting the key material
// which is used in PBES2.
type Cipher interface {
	// KeySize returns the key size of the cipher, in bytes.
	KeySize() int
	// Encrypt encrypts the key material. The returned AlgorithmIdentifier is
	// the algorithm identifier used for encryption including parameters.
	Encrypt(rand io.Reader, key, plaintext []byte) (*pkix.AlgorithmIdentifier, []byte, error)
	// Decrypt decrypts the key material. The parameters are the parameters from the
	// DER-encoded AlgorithmIdentifier's.
	Decrypt(key []byte, parameters *asn1.RawValue, ciphertext []byte) ([]byte, error)
	// OID returns the OID of the cipher specified.
	OID() asn1.ObjectIdentifier
}

var ciphers = make(map[string]func() Cipher)

// RegisterCipher registers a function that returns a new instance of the given
// cipher. This allows the library to support client-provided ciphers.
func RegisterCipher(oid asn1.ObjectIdentifier, cipher func() Cipher) {
	ciphers[oid.String()] = cipher
}

// GetCipher returns an instance of the cipher specified by the given algorithm identifier.
func GetCipher(alg pkix.AlgorithmIdentifier) (Cipher, error) {
	oid := alg.Algorithm.String()
	if oid == oidSM4.String() {
		if len(alg.Parameters.Bytes) != 0 || len(alg.Parameters.FullBytes) != 0 {
			return SM4CBC, nil
		} else {
			return SM4ECB, nil
		}
	}
	newCipher, ok := ciphers[oid]
	if !ok {
		return nil, fmt.Errorf("pbes: unsupported cipher (OID: %s)", oid)
	}
	return newCipher(), nil
}

type baseBlockCipher struct {
	oid      asn1.ObjectIdentifier
	keySize  int
	newBlock func(key []byte) (cipher.Block, error)
}

func (b *baseBlockCipher) KeySize() int {
	return b.keySize
}

func (b *baseBlockCipher) OID() asn1.ObjectIdentifier {
	return b.oid
}

type ecbBlockCipher struct {
	baseBlockCipher
}

func (ecb *ecbBlockCipher) Encrypt(rand io.Reader, key, plaintext []byte) (*pkix.AlgorithmIdentifier, []byte, error) {
	block, err := ecb.newBlock(key)
	if err != nil {
		return nil, nil, err
	}
	mode := smcipher.NewECBEncrypter(block)
	pkcs7 := padding.NewPKCS7Padding(uint(block.BlockSize()))
	plaintext = pkcs7.Pad(plaintext)
	ciphertext := make([]byte, len(plaintext))
	mode.CryptBlocks(ciphertext, plaintext)

	encryptionScheme := pkix.AlgorithmIdentifier{
		Algorithm: ecb.oid,
	}

	return &encryptionScheme, ciphertext, nil
}

func (ecb *ecbBlockCipher) Decrypt(key []byte, parameters *asn1.RawValue, ciphertext []byte) ([]byte, error) {
	block, err := ecb.newBlock(key)
	if err != nil {
		return nil, err
	}
	mode := smcipher.NewECBDecrypter(block)
	plaintext := make([]byte, len(ciphertext))
	mode.CryptBlocks(plaintext, ciphertext)
	pkcs7 := padding.NewPKCS7Padding(uint(block.BlockSize()))
	unpadded, err := pkcs7.ConstantTimeUnpad(plaintext)
	if err != nil { // In order to be compatible with some implementations without padding
		return plaintext, nil
	}
	return unpadded, nil
}

type cbcBlockCipher struct {
	baseBlockCipher
	ivSize int
}

func (c *cbcBlockCipher) Encrypt(rand io.Reader, key, plaintext []byte) (*pkix.AlgorithmIdentifier, []byte, error) {
	block, err := c.newBlock(key)
	if err != nil {
		return nil, nil, err
	}

	iv := make([]byte, c.ivSize)
	if _, err := rand.Read(iv); err != nil {
		return nil, nil, err
	}

	ciphertext, err := cbcEncrypt(block, iv, plaintext)
	if err != nil {
		return nil, nil, err
	}

	marshalledIV, err := asn1.Marshal(iv)
	if err != nil {
		return nil, nil, err
	}

	encryptionScheme := pkix.AlgorithmIdentifier{
		Algorithm:  c.oid,
		Parameters: asn1.RawValue{FullBytes: marshalledIV},
	}

	return &encryptionScheme, ciphertext, nil
}

func (c *cbcBlockCipher) Decrypt(key []byte, parameters *asn1.RawValue, ciphertext []byte) ([]byte, error) {
	block, err := c.newBlock(key)
	if err != nil {
		return nil, err
	}

	var iv []byte
	if _, err := asn1.Unmarshal(parameters.FullBytes, &iv); err != nil {
		return nil, errors.New("pbes: invalid cipher parameters")
	}

	return cbcDecrypt(block, iv, ciphertext)
}

func cbcEncrypt(block cipher.Block, iv, plaintext []byte) ([]byte, error) {
	mode := cipher.NewCBCEncrypter(block, iv)
	pkcs7 := padding.NewPKCS7Padding(uint(block.BlockSize()))
	plainText := pkcs7.Pad(plaintext)
	ciphertext := make([]byte, len(plainText))
	mode.CryptBlocks(ciphertext, plainText)
	return ciphertext, nil
}

func cbcDecrypt(block cipher.Block, iv, ciphertext []byte) ([]byte, error) {
	mode := cipher.NewCBCDecrypter(block, iv)
	pkcs7 := padding.NewPKCS7Padding(uint(block.BlockSize()))
	plaintext := make([]byte, len(ciphertext))
	mode.CryptBlocks(plaintext, ciphertext)
	return pkcs7.ConstantTimeUnpad(plaintext)
}

type gcmBlockCipher struct {
	baseBlockCipher
	nonceSize int
}

// https://datatracker.ietf.org/doc/rfc5084/
//
//	GCMParameters ::= SEQUENCE {
//		aes-nonce        OCTET STRING, -- recommended size is 12 octets
//		aes-ICVlen       AES-GCM-ICVlen DEFAULT 12 }
type gcmParameters struct {
	Nonce  []byte
	ICVLen int `asn1:"default:12,optional"`
}

func (c *gcmBlockCipher) Encrypt(rand io.Reader, key, plaintext []byte) (*pkix.AlgorithmIdentifier, []byte, error) {
	block, err := c.newBlock(key)
	if err != nil {
		return nil, nil, err
	}

	nonce := make([]byte, c.nonceSize)
	if _, err := rand.Read(nonce); err != nil {
		return nil, nil, err
	}

	aead, err := cipher.NewGCMWithNonceSize(block, c.nonceSize)
	if err != nil {
		return nil, nil, err
	}
	ciphertext := aead.Seal(nil, nonce, plaintext, nil)
	paramSeq := gcmParameters{
		Nonce:  nonce,
		ICVLen: aead.Overhead(),
	}
	paramBytes, err := asn1.Marshal(paramSeq)
	if err != nil {
		return nil, nil, err
	}
	encryptionAlgorithm := pkix.AlgorithmIdentifier{
		Algorithm: c.oid,
		Parameters: asn1.RawValue{
			FullBytes: paramBytes,
		},
	}
	return &encryptionAlgorithm, ciphertext, nil
}

func (c *gcmBlockCipher) Decrypt(key []byte, parameters *asn1.RawValue, ciphertext []byte) ([]byte, error) {
	block, err := c.newBlock(key)
	if err != nil {
		return nil, err
	}
	params := gcmParameters{}
	_, err = asn1.Unmarshal(parameters.FullBytes, &params)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCMWithNonceSize(block, len(params.Nonce))
	if err != nil {
		return nil, err
	}
	if params.ICVLen != aead.Overhead() {
		return nil, errors.New("pbes: we do not support non-standard tag size")
	}

	return aead.Open(nil, params.Nonce, ciphertext, nil)
}
