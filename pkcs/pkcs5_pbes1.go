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

// Key returns the key derived from the password according PBKDF1.
func (pbes1 *PBES1) Key(password []byte) ([]byte, error) {
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
		return nil, errors.New("pkcs5: unsupported pbes1 cipher")
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

func (pbes1 *PBES1) Decrypt(password, ciphertext []byte) ([]byte, KDFParameters, error) {
	key, err := pbes1.Key(password)
	if err != nil {
		return nil, nil, err
	}
	var block cipher.Block
	switch {
	case pbes1.Algorithm.Algorithm.Equal(pbeWithMD2AndDESCBC) ||
		pbes1.Algorithm.Algorithm.Equal(pbeWithMD5AndDESCBC) ||
		pbes1.Algorithm.Algorithm.Equal(pbeWithSHA1AndDESCBC):
		block, err = des.NewCipher(key[:8])
	case pbes1.Algorithm.Algorithm.Equal(pbeWithMD2AndRC2CBC) ||
		pbes1.Algorithm.Algorithm.Equal(pbeWithMD5AndRC2CBC) ||
		pbes1.Algorithm.Algorithm.Equal(pbeWithSHA1AndRC2CBC):
		block, err = rc2.NewCipher(key[:8])
	default:
		return nil, nil, errors.New("pkcs5: unsupported pbes1 cipher")
	}
	if err != nil {
		return nil, nil, err
	}
	plaintext, err := cbcDecrypt(block, key[8:16], ciphertext)
	if err != nil {
		return nil, nil, err
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
