// Copyright 2024 Sun Yimin. All rights reserved.
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file.

package pkcs7

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"errors"

	"github.com/emmansun/gmsm/sm2"
	"github.com/emmansun/gmsm/smx509"
)

// Session is an interface that provides methods to generate and encrypt/decrypt data keys
type Session interface {
	// GenerateDataKey returns the data key to be used for encryption
	GenerateDataKey(size int) ([]byte, error)

	// EncryptdDataKey encrypts the key with the provided certificate public key
	EncryptdDataKey(key []byte, cert *smx509.Certificate, opts any) ([]byte, error)

	// DecryptDataKey decrypts the key with the provided certificate private key
	DecryptDataKey(key []byte, priv crypto.PrivateKey, cert *smx509.Certificate, opts any) ([]byte, error)
}

// DefaultSession is the default implementation of Session without any special handling (stateless).
// Custom implementations can be provided to handle key reuse, cache, etc.
type DefaultSession struct{}

func (DefaultSession) GenerateDataKey(size int) ([]byte, error) {
	key := make([]byte, size)
	if _, err := rand.Read(key); err != nil {
		return nil, err
	}
	return key, nil
}

func (DefaultSession) EncryptdDataKey(key []byte, cert *smx509.Certificate, opts any) ([]byte, error) {
	switch pub := cert.PublicKey.(type) {
	case *rsa.PublicKey:
		return rsa.EncryptPKCS1v15(rand.Reader, pub, key)
	case *ecdsa.PublicKey:
		if pub.Curve == sm2.P256() {
			if isLegacyCFCA, ok := opts.(bool); ok && isLegacyCFCA {
				encryptedKey, err := sm2.Encrypt(rand.Reader, pub, key, sm2.NewPlainEncrypterOpts(sm2.MarshalUncompressed, sm2.C1C2C3))
				if err != nil {
					return nil, err
				}
				return encryptedKey[1:], nil
			} else {
				return sm2.EncryptASN1(rand.Reader, pub, key)
			}
		}
	}
	return nil, errors.New("pkcs7: only supports RSA/SM2 key")
}

func (DefaultSession) DecryptDataKey(key []byte, priv crypto.PrivateKey, cert *smx509.Certificate, opts any) ([]byte, error) {
	if decrypter, ok := priv.(crypto.Decrypter); ok {
		// Generic case to handle anything that provides the crypto.Decrypter interface.
		encryptedKey := key
		var decrypterOpts crypto.DecrypterOpts

		if _, isSM2Key := priv.(*sm2.PrivateKey); isSM2Key {
			if isLegacyCFCA, ok := opts.(bool); ok && isLegacyCFCA {
				encryptedKey = make([]byte, len(key)+1)
				encryptedKey[0] = 0x04
				copy(encryptedKey[1:], key)
				decrypterOpts = sm2.NewPlainDecrypterOpts(sm2.C1C2C3)
			}
		}

		contentKey, err := decrypter.Decrypt(rand.Reader, encryptedKey, decrypterOpts)
		if err != nil {
			return nil, err
		}
		return contentKey, nil
	}
	return nil, ErrUnsupportedAlgorithm
}
