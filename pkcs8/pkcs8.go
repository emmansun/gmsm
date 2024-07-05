// Package pkcs8 implements functions to parse and convert private keys in PKCS#8 format with ShangMi(SM) support, as defined in RFC5208 and RFC5958.
package pkcs8

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"errors"

	"github.com/emmansun/gmsm/pkcs"
	"github.com/emmansun/gmsm/sm2"
	"github.com/emmansun/gmsm/sm9"
	"github.com/emmansun/gmsm/smx509"
)

type Opts = pkcs.PBES2Opts
type PBKDF2Opts = pkcs.PBKDF2Opts
type ScryptOpts = pkcs.ScryptOpts

var DefaultOpts = pkcs.DefaultOpts
var SM3 = pkcs.SM3
var SHA1 = pkcs.SHA1
var SHA224 = pkcs.SHA224
var SHA256 = pkcs.SHA256
var SHA384 = pkcs.SHA384
var SHA512 = pkcs.SHA512
var SHA512_224 = pkcs.SHA512_224
var SHA512_256 = pkcs.SHA512_256

// for encrypted private-key information
type encryptedPrivateKeyInfo struct {
	EncryptionAlgorithm pkix.AlgorithmIdentifier
	EncryptedData       []byte
}

// ParsePrivateKey parses a DER-encoded PKCS#8 private key.
// Password can be nil.
// This is equivalent to ParsePKCS8PrivateKey.
func ParsePrivateKey(der []byte, password []byte) (any, pkcs.KDFParameters, error) {
	// No password provided, assume the private key is unencrypted
	if len(password) == 0 {
		privateKey, err := smx509.ParsePKCS8PrivateKey(der)
		return privateKey, nil, err
	}

	// Use the password provided to decrypt the private key
	var privKey encryptedPrivateKeyInfo
	if _, err := asn1.Unmarshal(der, &privKey); err != nil {
		if block, _ := pem.Decode(der); block != nil {
			return nil, nil, errors.New("pkcs8: this method just supports DER-encoded key")
		}
		return nil, nil, errors.New("pkcs8: only PKCS #5 v2.0 supported")
	}

	var kdfParams pkcs.KDFParameters
	var decryptedKey []byte
	var err error
	switch {
	case pkcs.IsPBES2(privKey.EncryptionAlgorithm):
		var params pkcs.PBES2Params
		if _, err := asn1.Unmarshal(privKey.EncryptionAlgorithm.Parameters.FullBytes, &params); err != nil {
			return nil, nil, errors.New("pkcs8: invalid PBES2 parameters")
		}
		decryptedKey, kdfParams, err = params.Decrypt(password, privKey.EncryptedData)
	case pkcs.IsPBES1(privKey.EncryptionAlgorithm):
		pbes1 := &pkcs.PBES1{Algorithm: privKey.EncryptionAlgorithm}
		decryptedKey, kdfParams, err = pbes1.Decrypt(password, privKey.EncryptedData)
	default:
		return nil, nil, errors.New("pkcs8: only part of PBES1/PBES2 supported")
	}
	if err != nil {
		return nil, nil, err
	}
	key, err := smx509.ParsePKCS8PrivateKey(decryptedKey)
	if err != nil {
		return nil, nil, errors.New("pkcs8: incorrect password? failed to parse private key while ParsePKCS8PrivateKey: " + err.Error())
	}
	return key, kdfParams, nil
}

// MarshalPrivateKey encodes a private key into DER-encoded PKCS#8 with the given options.
// Password can be nil.
func MarshalPrivateKey(priv any, password []byte, encrypter pkcs.PBESEncrypter) ([]byte, error) {
	if len(password) == 0 {
		return smx509.MarshalPKCS8PrivateKey(priv)
	}

	if encrypter == nil {
		encrypter = DefaultOpts
	}

	// Convert private key into PKCS8 format
	pkey, err := smx509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return nil, err
	}

	encryptionAlgorithm, encryptedKey, err := encrypter.Encrypt(rand.Reader, password, pkey)
	if err != nil {
		return nil, err
	}

	encryptedPkey := encryptedPrivateKeyInfo{
		EncryptionAlgorithm: *encryptionAlgorithm,
		EncryptedData:       encryptedKey,
	}

	return asn1.Marshal(encryptedPkey)
}

// ParsePKCS8PrivateKey parses encrypted/unencrypted private keys in PKCS#8 format.
// To parse encrypted private keys, a password of []byte type should be provided to the function as the second parameter.
func ParsePKCS8PrivateKey(der []byte, v ...[]byte) (any, error) {
	var password []byte
	if len(v) > 0 {
		password = v[0]
	}
	privateKey, _, err := ParsePrivateKey(der, password)
	return privateKey, err
}

// ParsePKCS8PrivateKeyRSA parses encrypted/unencrypted private keys in PKCS#8 format.
// To parse encrypted private keys, a password of []byte type should be provided to the function as the second parameter.
func ParsePKCS8PrivateKeyRSA(der []byte, v ...[]byte) (*rsa.PrivateKey, error) {
	key, err := ParsePKCS8PrivateKey(der, v...)
	if err != nil {
		return nil, err
	}
	typedKey, ok := key.(*rsa.PrivateKey)
	if !ok {
		return nil, errors.New("pkcs8: key block is not of type RSA")
	}
	return typedKey, nil
}

// ParsePKCS8PrivateKeyECDSA parses encrypted/unencrypted private keys in PKCS#8 format.
// To parse encrypted private keys, a password of []byte type should be provided to the function as the second parameter.
func ParsePKCS8PrivateKeyECDSA(der []byte, v ...[]byte) (*ecdsa.PrivateKey, error) {
	key, err := ParsePKCS8PrivateKey(der, v...)
	if err != nil {
		return nil, err
	}
	typedKey, ok := key.(*ecdsa.PrivateKey)
	if !ok {
		return nil, errors.New("pkcs8: key block is not of type ECDSA")
	}
	return typedKey, nil
}

// ParsePKCS8PrivateKeySM2 parses encrypted/unencrypted SM2 private key in PKCS#8 format.
// To parse encrypted private keys, a password of []byte type should be provided to the function as the second parameter.
func ParsePKCS8PrivateKeySM2(der []byte, v ...[]byte) (*sm2.PrivateKey, error) {
	key, err := ParsePKCS8PrivateKey(der, v...)
	if err != nil {
		return nil, err
	}
	typedKey, ok := key.(*sm2.PrivateKey)
	if !ok {
		return nil, errors.New("pkcs8: key block is not of type SM2")
	}
	return typedKey, nil
}

// ParseSM9SignMasterPrivateKey parses encrypted/unencrypted SM9 sign master private key in PKCS#8 format.
// To parse encrypted private keys, a password of []byte type should be provided to the function as the second parameter.
func ParseSM9SignMasterPrivateKey(der []byte, v ...[]byte) (*sm9.SignMasterPrivateKey, error) {
	key, err := ParsePKCS8PrivateKey(der, v...)
	if err != nil {
		return nil, err
	}
	typedKey, ok := key.(*sm9.SignMasterPrivateKey)
	if !ok {
		return nil, errors.New("pkcs8: key block is not of type SM9 sign master private key")
	}
	return typedKey, nil
}

// ParseSM9SignPrivateKey parses encrypted/unencrypted SM9 sign private key in PKCS#8 format.
// To parse encrypted private keys, a password of []byte type should be provided to the function as the second parameter.
func ParseSM9SignPrivateKey(der []byte, v ...[]byte) (*sm9.SignPrivateKey, error) {
	key, err := ParsePKCS8PrivateKey(der, v...)
	if err != nil {
		return nil, err
	}
	typedKey, ok := key.(*sm9.SignPrivateKey)
	if !ok {
		return nil, errors.New("pkcs8: key block is not of type SM9 sign user private key")
	}
	return typedKey, nil
}

// ParseSM9EncryptMasterPrivateKey parses encrypted/unencrypted SM9 encrypt master private key in PKCS#8 format.
// To parse encrypted private keys, a password of []byte type should be provided to the function as the second parameter.
func ParseSM9EncryptMasterPrivateKey(der []byte, v ...[]byte) (*sm9.EncryptMasterPrivateKey, error) {
	key, err := ParsePKCS8PrivateKey(der, v...)
	if err != nil {
		return nil, err
	}
	typedKey, ok := key.(*sm9.EncryptMasterPrivateKey)
	if !ok {
		return nil, errors.New("pkcs8: key block is not of type SM9 encrypt master private key")
	}
	return typedKey, nil
}

// ParseSM9EncryptPrivateKey parses encrypted/unencrypted SM9 encrypt private key in PKCS#8 format.
// To parse encrypted private keys, a password of []byte type should be provided to the function as the second parameter.
func ParseSM9EncryptPrivateKey(der []byte, v ...[]byte) (*sm9.EncryptPrivateKey, error) {
	key, err := ParsePKCS8PrivateKey(der, v...)
	if err != nil {
		return nil, err
	}
	typedKey, ok := key.(*sm9.EncryptPrivateKey)
	if !ok {
		return nil, errors.New("pkcs8: key block is not of type SM9 encrypt user private key")
	}
	return typedKey, nil
}

// ConvertPrivateKeyToPKCS8 converts the private key into PKCS#8 format.
// To encrypt the private key, the password of []byte type should be provided as the second parameter.
func ConvertPrivateKeyToPKCS8(priv any, v ...[]byte) ([]byte, error) {
	var password []byte
	if len(v) > 0 {
		password = v[0]
	}
	return MarshalPrivateKey(priv, password, nil)
}
