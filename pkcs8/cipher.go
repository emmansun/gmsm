package pkcs8

import (
	"crypto/cipher"
	"crypto/rand"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"

	"github.com/emmansun/gmsm/padding"
)

func genRandom(len int) ([]byte, error) {
	value := make([]byte, len)
	_, err := rand.Read(value)
	return value, err
}

type cbcBlockCipher struct {
	oid      asn1.ObjectIdentifier
	ivSize   int
	keySize  int
	newBlock func(key []byte) (cipher.Block, error)
}

func (c cbcBlockCipher) KeySize() int {
	return c.keySize
}

func (c cbcBlockCipher) OID() asn1.ObjectIdentifier {
	return c.oid
}

func (c cbcBlockCipher) Encrypt(key, plaintext []byte) (*pkix.AlgorithmIdentifier, []byte, error) {
	block, err := c.newBlock(key)
	if err != nil {
		return nil, nil, err
	}
	iv, err := genRandom(c.ivSize)
	if err != nil {
		return nil, nil, err
	}
	ciphertext, err := cbcEncrypt(block, key, iv, plaintext)
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

func (c cbcBlockCipher) Decrypt(key []byte, parameters *asn1.RawValue, encryptedKey []byte) ([]byte, error) {
	block, err := c.newBlock(key)
	if err != nil {
		return nil, err
	}

	var iv []byte
	if _, err := asn1.Unmarshal(parameters.FullBytes, &iv); err != nil {
		return nil, errors.New("pkcs8: invalid cipher parameters")
	}

	return cbcDecrypt(block, key, iv, encryptedKey)
}

func cbcEncrypt(block cipher.Block, key, iv, plaintext []byte) ([]byte, error) {
	mode := cipher.NewCBCEncrypter(block, iv)
	pkcs7 := padding.NewPKCS7Padding(uint(block.BlockSize()))
	plainText := pkcs7.Pad(plaintext)
	ciphertext := make([]byte, len(plainText))
	mode.CryptBlocks(ciphertext, plainText)
	return ciphertext, nil
}

func cbcDecrypt(block cipher.Block, key, iv, ciphertext []byte) ([]byte, error) {
	mode := cipher.NewCBCDecrypter(block, iv)
	pkcs7 := padding.NewPKCS7Padding(uint(block.BlockSize()))
	plaintext := make([]byte, len(ciphertext))
	mode.CryptBlocks(plaintext, ciphertext)
	return pkcs7.Unpad(plaintext)
}

type gcmBlockCipher struct {
	oid       asn1.ObjectIdentifier
	nonceSize int
	keySize   int
	newBlock  func(key []byte) (cipher.Block, error)
}

// http://javadoc.iaik.tugraz.at/iaik_jce/current/index.html?iaik/security/cipher/GCMParameters.html
type gcmParameters struct {
	Nonce  []byte `asn1:"tag:4"`
	ICVLen int
}

func (c gcmBlockCipher) KeySize() int {
	return c.keySize
}

func (c gcmBlockCipher) OID() asn1.ObjectIdentifier {
	return c.oid
}

func (c gcmBlockCipher) Encrypt(key, plaintext []byte) (*pkix.AlgorithmIdentifier, []byte, error) {
	block, err := c.newBlock(key)
	if err != nil {
		return nil, nil, err
	}
	nonce, err := genRandom(c.nonceSize)
	if err != nil {
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

func (c gcmBlockCipher) Decrypt(key []byte, parameters *asn1.RawValue, encryptedKey []byte) ([]byte, error) {
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
		return nil, errors.New("pkcs8: invalid tag size")
	}

	return aead.Open(nil, params.Nonce, encryptedKey, nil)
}
