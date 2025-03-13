package sm9

import (
	"crypto/cipher"
	"crypto/subtle"
	"io"

	_cipher "github.com/emmansun/gmsm/cipher"
	"github.com/emmansun/gmsm/padding"
	"github.com/emmansun/gmsm/sm4"
)

// EncrypterOpts is an interface implemented by detail encrypt/decrypt mode.
type EncrypterOpts interface {
	// GetEncryptType returns the encrypt type/mode.
	GetEncryptType() encryptType
	// GetKeySize returns key size used by this encrypt mode.
	GetKeySize(plaintext []byte) int
	// Encrypt encrypts the plaintext with the key, returns ciphertext.
	Encrypt(rand io.Reader, key, plaintext []byte) ([]byte, error)
	// Decrypt decrypts the ciphertext with the key, returns plaintext.
	Decrypt(key, ciphertext []byte) ([]byte, error)
}

// XOREncrypterOpts represents XOR mode.
type XOREncrypterOpts struct{}

func (opts *XOREncrypterOpts) GetEncryptType() encryptType {
	return ENC_TYPE_XOR
}

func (opts *XOREncrypterOpts) GetKeySize(plaintext []byte) int {
	return len(plaintext)
}

func (opts *XOREncrypterOpts) Encrypt(rand io.Reader, key, plaintext []byte) ([]byte, error) {
	subtle.XORBytes(key, key, plaintext)
	return key, nil
}

func (opts *XOREncrypterOpts) Decrypt(key, ciphertext []byte) ([]byte, error) {
	if len(ciphertext) == 0 {
		return nil, ErrDecryption
	}
	subtle.XORBytes(key, ciphertext, key)
	return key, nil
}

type newCipher func(key []byte) (cipher.Block, error)

type baseBlockEncrypterOpts struct {
	encryptType   encryptType
	newCipher     newCipher
	cipherKeySize int
}

func (opts *baseBlockEncrypterOpts) GetEncryptType() encryptType {
	return opts.encryptType
}

func (opts *baseBlockEncrypterOpts) GetKeySize(plaintext []byte) int {
	return opts.cipherKeySize
}

// CBCEncrypterOpts represents CBC (Cipher block chaining) mode.
type CBCEncrypterOpts struct {
	baseBlockEncrypterOpts
	padding padding.Padding
}

func NewCBCEncrypterOpts(padding padding.Padding, newCipher newCipher, keySize int) EncrypterOpts {
	opts := new(CBCEncrypterOpts)
	opts.encryptType = ENC_TYPE_CBC
	opts.padding = padding
	opts.newCipher = newCipher
	opts.cipherKeySize = keySize
	return opts
}

// Encrypt encrypts the plaintext with the key, includes generated IV at the beginning of the ciphertext.
func (opts *CBCEncrypterOpts) Encrypt(rand io.Reader, key, plaintext []byte) ([]byte, error) {
	block, err := opts.newCipher(key)
	if err != nil {
		return nil, err
	}
	paddedPlainText := opts.padding.Pad(plaintext)
	blockSize := block.BlockSize()
	ciphertext := make([]byte, blockSize+len(paddedPlainText))
	iv := ciphertext[:blockSize]
	if _, err := io.ReadFull(rand, iv); err != nil {
		return nil, err
	}
	mode := cipher.NewCBCEncrypter(block, iv)
	mode.CryptBlocks(ciphertext[blockSize:], paddedPlainText)
	return ciphertext, nil
}

func (opts *CBCEncrypterOpts) Decrypt(key, ciphertext []byte) ([]byte, error) {
	block, err := opts.newCipher(key)
	if err != nil {
		return nil, err
	}
	blockSize := block.BlockSize()
	if len(ciphertext) <= blockSize {
		return nil, ErrDecryption
	}
	iv := ciphertext[:blockSize]
	ciphertext = ciphertext[blockSize:]
	plaintext := make([]byte, len(ciphertext))
	mode := cipher.NewCBCDecrypter(block, iv)
	mode.CryptBlocks(plaintext, ciphertext)
	return opts.padding.Unpad(plaintext)
}

// ECBEncrypterOpts represents ECB (Electronic Code Book) mode.
type ECBEncrypterOpts struct {
	baseBlockEncrypterOpts
	padding padding.Padding
}

func NewECBEncrypterOpts(padding padding.Padding, newCipher newCipher, keySize int) EncrypterOpts {
	opts := new(ECBEncrypterOpts)
	opts.encryptType = ENC_TYPE_ECB
	opts.padding = padding
	opts.newCipher = newCipher
	opts.cipherKeySize = keySize
	return opts
}

func (opts *ECBEncrypterOpts) Encrypt(rand io.Reader, key, plaintext []byte) ([]byte, error) {
	block, err := opts.newCipher(key)
	if err != nil {
		return nil, err
	}
	paddedPlainText := opts.padding.Pad(plaintext)
	ciphertext := make([]byte, len(paddedPlainText))
	mode := _cipher.NewECBEncrypter(block)
	mode.CryptBlocks(ciphertext, paddedPlainText)
	return ciphertext, nil
}

func (opts *ECBEncrypterOpts) Decrypt(key, ciphertext []byte) ([]byte, error) {
	block, err := opts.newCipher(key)
	if err != nil {
		return nil, err
	}
	if len(ciphertext) == 0 {
		return nil, ErrDecryption
	}
	plaintext := make([]byte, len(ciphertext))
	mode := _cipher.NewECBDecrypter(block)
	mode.CryptBlocks(plaintext, ciphertext)
	return opts.padding.Unpad(plaintext)
}

// CFBEncrypterOpts represents CFB (Cipher Feedback) mode.
type CFBEncrypterOpts struct {
	baseBlockEncrypterOpts
}

func NewCFBEncrypterOpts(newCipher newCipher, keySize int) EncrypterOpts {
	opts := new(CFBEncrypterOpts)
	opts.encryptType = ENC_TYPE_CFB
	opts.newCipher = newCipher
	opts.cipherKeySize = keySize
	return opts
}

// Encrypt encrypts the plaintext with the key, includes generated IV at the beginning of the ciphertext.
func (opts *CFBEncrypterOpts) Encrypt(rand io.Reader, key, plaintext []byte) ([]byte, error) {
	block, err := opts.newCipher(key)
	if err != nil {
		return nil, err
	}
	blockSize := block.BlockSize()
	ciphertext := make([]byte, blockSize+len(plaintext))
	iv := ciphertext[:blockSize]
	if _, err := io.ReadFull(rand, iv); err != nil {
		return nil, err
	}
	stream := cipher.NewCFBEncrypter(block, iv)
	stream.XORKeyStream(ciphertext[blockSize:], plaintext)
	return ciphertext, nil
}

func (opts *CFBEncrypterOpts) Decrypt(key, ciphertext []byte) ([]byte, error) {
	block, err := opts.newCipher(key)
	if err != nil {
		return nil, err
	}
	blockSize := block.BlockSize()
	if len(ciphertext) <= blockSize {
		return nil, ErrDecryption
	}
	iv := ciphertext[:blockSize]
	ciphertext = ciphertext[blockSize:]
	plaintext := make([]byte, len(ciphertext))
	stream := cipher.NewCFBDecrypter(block, iv)
	stream.XORKeyStream(plaintext, ciphertext)
	return plaintext, nil
}

// OFBEncrypterOpts represents OFB (Output Feedback) mode.
type OFBEncrypterOpts struct {
	baseBlockEncrypterOpts
}

func NewOFBEncrypterOpts(newCipher newCipher, keySize int) EncrypterOpts {
	opts := new(OFBEncrypterOpts)
	opts.encryptType = ENC_TYPE_OFB
	opts.newCipher = newCipher
	opts.cipherKeySize = keySize
	return opts
}

// Encrypt encrypts the plaintext with the key, includes generated IV at the beginning of the ciphertext.
func (opts *OFBEncrypterOpts) Encrypt(rand io.Reader, key, plaintext []byte) ([]byte, error) {
	block, err := opts.newCipher(key)
	if err != nil {
		return nil, err
	}
	blockSize := block.BlockSize()
	ciphertext := make([]byte, blockSize+len(plaintext))
	iv := ciphertext[:blockSize]
	if _, err := io.ReadFull(rand, iv); err != nil {
		return nil, err
	}
	stream := cipher.NewOFB(block, iv)
	stream.XORKeyStream(ciphertext[blockSize:], plaintext)
	return ciphertext, nil
}

func (opts *OFBEncrypterOpts) Decrypt(key, ciphertext []byte) ([]byte, error) {
	block, err := opts.newCipher(key)
	if err != nil {
		return nil, err
	}
	blockSize := block.BlockSize()
	if len(ciphertext) <= blockSize {
		return nil, ErrDecryption
	}
	iv := ciphertext[:blockSize]
	ciphertext = ciphertext[blockSize:]
	plaintext := make([]byte, len(ciphertext))
	stream := cipher.NewOFB(block, iv)
	stream.XORKeyStream(plaintext, ciphertext)
	return plaintext, nil
}

// DefaultEncrypterOpts default option represents XOR mode
var DefaultEncrypterOpts = new(XOREncrypterOpts)

// SM4ECBEncrypterOpts option represents SM4 ECB mode
var SM4ECBEncrypterOpts = NewECBEncrypterOpts(padding.NewPKCS7Padding(sm4.BlockSize), sm4.NewCipher, sm4.BlockSize)

// SM4CBCEncrypterOpts option represents SM4 CBC mode
var SM4CBCEncrypterOpts = NewCBCEncrypterOpts(padding.NewPKCS7Padding(sm4.BlockSize), sm4.NewCipher, sm4.BlockSize)

// SM4CFBEncrypterOpts option represents SM4 CFB mode
var SM4CFBEncrypterOpts = NewCFBEncrypterOpts(sm4.NewCipher, sm4.BlockSize)

// SM4OFBEncrypterOpts option represents SM4 OFB mode
var SM4OFBEncrypterOpts = NewOFBEncrypterOpts(sm4.NewCipher, sm4.BlockSize)

func shangMiEncrypterOpts(encType encryptType) EncrypterOpts {
	switch encType {
	case ENC_TYPE_XOR:
		return DefaultEncrypterOpts
	case ENC_TYPE_CBC:
		return SM4CBCEncrypterOpts
	case ENC_TYPE_ECB:
		return SM4ECBEncrypterOpts
	case ENC_TYPE_CFB:
		return SM4CFBEncrypterOpts
	case ENC_TYPE_OFB:
		return SM4OFBEncrypterOpts
	}
	return nil
}
