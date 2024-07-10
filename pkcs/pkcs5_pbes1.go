package pkcs

import (
	"crypto/cipher"
	"crypto/des"
	"crypto/md5"
	"crypto/sha1"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"hash"
	"io"

	"github.com/emmansun/gmsm/pkcs/internal/md2"
	"github.com/emmansun/gmsm/pkcs/internal/rc2"
)

var (
	pbeWithMD2AndDESCBC  = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 5, 1}
	pbeWithMD2AndRC2CBC  = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 5, 4}
	pbeWithMD5AndDESCBC  = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 5, 3}
	pbeWithMD5AndRC2CBC  = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 5, 6}
	pbeWithSHA1AndDESCBC = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 5, 10}
	pbeWithSHA1AndRC2CBC = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 5, 11}
)

type pbeParameter struct {
	Salt      []byte
	Iteration int
}

// PBES1 implements the Password-Based Encryption Scheme 1.
type PBES1 struct {
	Algorithm pkix.AlgorithmIdentifier
}

// newPBES1 creates a new PBES1 instance.
func newPBES1(rand io.Reader, oid asn1.ObjectIdentifier, saltLen, iterations int) (*PBES1, error) {
	salt := make([]byte, saltLen)
	if _, err := rand.Read(salt); err != nil {
		return nil, err
	}
	param := pbeParameter{Salt: salt, Iteration: iterations}
	marshalledParams, err := asn1.Marshal(param)
	if err != nil {
		return nil, err
	}
	return &PBES1{
		Algorithm: pkix.AlgorithmIdentifier{
			Algorithm:  oid,
			Parameters: asn1.RawValue{FullBytes: marshalledParams},
		},
	}, nil
}

func NewPbeWithMD2AndDESCBC(rand io.Reader, saltLen, iterations int) (*PBES1, error) {
	return newPBES1(rand, pbeWithMD2AndDESCBC, saltLen, iterations)
}

func NewPbeWithMD2AndRC2CBC(rand io.Reader, saltLen, iterations int) (*PBES1, error) {
	return newPBES1(rand, pbeWithMD2AndRC2CBC, saltLen, iterations)
}

func NewPbeWithMD5AndDESCBC(rand io.Reader, saltLen, iterations int) (*PBES1, error) {
	return newPBES1(rand, pbeWithMD5AndDESCBC, saltLen, iterations)
}

func NewPbeWithMD5AndRC2CBC(rand io.Reader, saltLen, iterations int) (*PBES1, error) {
	return newPBES1(rand, pbeWithMD5AndRC2CBC, saltLen, iterations)
}

func NewPbeWithSHA1AndDESCBC(rand io.Reader, saltLen, iterations int) (*PBES1, error) {
	return newPBES1(rand, pbeWithSHA1AndDESCBC, saltLen, iterations)
}

func NewPbeWithSHA1AndRC2CBC(rand io.Reader, saltLen, iterations int) (*PBES1, error) {
	return newPBES1(rand, pbeWithSHA1AndRC2CBC, saltLen, iterations)
}

// Key returns the key derived from the password according PBKDF1.
func (pbes1 *PBES1) key(password []byte) ([]byte, error) {
	param := new(pbeParameter)
	if _, err := asn1.Unmarshal(pbes1.Algorithm.Parameters.FullBytes, param); err != nil {
		return nil, err
	}
	var hash hash.Hash
	switch {
	case pbes1.Algorithm.Algorithm.Equal(pbeWithMD2AndDESCBC) || pbes1.Algorithm.Algorithm.Equal(pbeWithMD2AndRC2CBC):
		hash = md2.New()
	case pbes1.Algorithm.Algorithm.Equal(pbeWithMD5AndDESCBC) || pbes1.Algorithm.Algorithm.Equal(pbeWithMD5AndRC2CBC):
		hash = md5.New()
	case pbes1.Algorithm.Algorithm.Equal(pbeWithSHA1AndDESCBC) || pbes1.Algorithm.Algorithm.Equal(pbeWithSHA1AndRC2CBC):
		hash = sha1.New()
	default:
		return nil, errors.New("pbes: unsupported pbes1 cipher")
	}
	hash.Write(password)
	hash.Write(param.Salt)
	key := hash.Sum(nil)
	for i := 1; i < param.Iteration; i++ {
		hash.Reset()
		hash.Write(key)
		key = hash.Sum(key[:0])
	}
	return key, nil
}

func (pbes1 *PBES1) newBlock(key []byte) (cipher.Block, error) {
	var block cipher.Block
	switch {
	case pbes1.Algorithm.Algorithm.Equal(pbeWithMD2AndDESCBC) ||
		pbes1.Algorithm.Algorithm.Equal(pbeWithMD5AndDESCBC) ||
		pbes1.Algorithm.Algorithm.Equal(pbeWithSHA1AndDESCBC):
		block, _ = des.NewCipher(key[:8])
	case pbes1.Algorithm.Algorithm.Equal(pbeWithMD2AndRC2CBC) ||
		pbes1.Algorithm.Algorithm.Equal(pbeWithMD5AndRC2CBC) ||
		pbes1.Algorithm.Algorithm.Equal(pbeWithSHA1AndRC2CBC):
		block, _ = rc2.NewCipher(key[:8])
	default:
		return nil, errors.New("pbes: unsupported pbes1 cipher")
	}
	return block, nil
}

func (pbes1 *PBES1) Encrypt(rand io.Reader, password, plaintext []byte) (*pkix.AlgorithmIdentifier, []byte, error) {
	key, err := pbes1.key(password)
	if err != nil {
		return nil, nil, err
	}
	block, err := pbes1.newBlock(key)
	if err != nil {
		return nil, nil, err
	}
	ciphertext, err := cbcEncrypt(block, key[8:16], plaintext)
	if err != nil {
		return nil, nil, err
	}
	return &pbes1.Algorithm, ciphertext, nil
}

func (pbes1 *PBES1) Decrypt(password, ciphertext []byte) ([]byte, KDFParameters, error) {
	key, err := pbes1.key(password)
	if err != nil {
		return nil, nil, err
	}
	block, err := pbes1.newBlock(key)
	if err != nil {
		return nil, nil, err
	}
	plaintext, err := cbcDecrypt(block, key[8:16], ciphertext)
	if err != nil {
		return nil, nil, ErrPBEDecryption
	}
	return plaintext, nil, nil
}

func IsPBES1(algorithm pkix.AlgorithmIdentifier) bool {
	return algorithm.Algorithm.Equal(pbeWithMD2AndDESCBC) ||
		algorithm.Algorithm.Equal(pbeWithMD2AndRC2CBC) ||
		algorithm.Algorithm.Equal(pbeWithMD5AndDESCBC) ||
		algorithm.Algorithm.Equal(pbeWithMD5AndRC2CBC) ||
		algorithm.Algorithm.Equal(pbeWithSHA1AndDESCBC) ||
		algorithm.Algorithm.Equal(pbeWithSHA1AndRC2CBC)
}
