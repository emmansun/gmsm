// Package pkcs8 implements functions to parse and convert private keys in PKCS#8 format, as defined in RFC5208 and RFC5958
package pkcs8

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"errors"
	"fmt"
	"hash"
	"strconv"

	"github.com/emmansun/gmsm/sm2"
	"github.com/emmansun/gmsm/sm3"
	"github.com/emmansun/gmsm/smx509"
)

// Hash identifies a cryptographic hash function that is implemented in another
// package.
type Hash uint

const (
	SHA1 Hash = 1 + iota
	SHA224
	SHA256
	SHA384
	SHA512
	SHA512_224
	SHA512_256
	SM3
)

// New returns a new hash.Hash calculating the given hash function. New panics
// if the hash function is not linked into the binary.
func (h Hash) New() hash.Hash {
	switch h {
	case SM3:
		return sm3.New()
	case SHA1:
		return sha1.New()
	case SHA224:
		return sha256.New224()
	case SHA256:
		return sha256.New()
	case SHA384:
		return sha512.New384()
	case SHA512:
		return sha512.New()
	case SHA512_224:
		return sha512.New512_224()
	case SHA512_256:
		return sha512.New512_256()

	}
	panic("pkcs8: requested hash function #" + strconv.Itoa(int(h)) + " is unavailable")
}

// DefaultOpts are the default options for encrypting a key if none are given.
// The defaults can be changed by the library user.
var DefaultOpts = &Opts{
	Cipher: AES256CBC,
	KDFOpts: PBKDF2Opts{
		SaltSize:       8,
		IterationCount: 10000,
		HMACHash:       SHA256,
	},
}

// KDFOpts contains options for a key derivation function.
// An implementation of this interface must be specified when encrypting a PKCS#8 key.
type KDFOpts interface {
	// DeriveKey derives a key of size bytes from the given password and salt.
	// It returns the key and the ASN.1-encodable parameters used.
	DeriveKey(password, salt []byte, size int) (key []byte, params KDFParameters, err error)
	// GetSaltSize returns the salt size specified.
	GetSaltSize() int
	// OID returns the OID of the KDF specified.
	OID() asn1.ObjectIdentifier
}

// KDFParameters contains parameters (salt, etc.) for a key deriviation function.
// It must be a ASN.1-decodable structure.
// An implementation of this interface is created when decoding an encrypted PKCS#8 key.
type KDFParameters interface {
	// DeriveKey derives a key of size bytes from the given password.
	// It uses the salt from the decoded parameters.
	DeriveKey(password []byte, size int) (key []byte, err error)
}

var kdfs = make(map[string]func() KDFParameters)

// RegisterKDF registers a function that returns a new instance of the given KDF
// parameters. This allows the library to support client-provided KDFs.
func RegisterKDF(oid asn1.ObjectIdentifier, params func() KDFParameters) {
	kdfs[oid.String()] = params
}

// for encrypted private-key information
type encryptedPrivateKeyInfo struct {
	EncryptionAlgorithm pkix.AlgorithmIdentifier
	EncryptedData       []byte
}

// Cipher represents a cipher for encrypting the key material.
type Cipher interface {
	// KeySize returns the key size of the cipher, in bytes.
	KeySize() int
	// Encrypt encrypts the key material.
	Encrypt(key, plaintext []byte) (*pkix.AlgorithmIdentifier, []byte, error)
	// Decrypt decrypts the key material.
	Decrypt(key []byte, parameters *asn1.RawValue, encryptedKey []byte) ([]byte, error)
	// OID returns the OID of the cipher specified.
	OID() asn1.ObjectIdentifier
}

var ciphers = make(map[string]func() Cipher)

// RegisterCipher registers a function that returns a new instance of the given
// cipher. This allows the library to support client-provided ciphers.
func RegisterCipher(oid asn1.ObjectIdentifier, cipher func() Cipher) {
	ciphers[oid.String()] = cipher
}

// Opts contains options for encrypting a PKCS#8 key.
type Opts struct {
	Cipher  Cipher
	KDFOpts KDFOpts
}

// Unecrypted PKCS8
var (
	oidPBES2 = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 5, 13}
)

type pbes2Params struct {
	KeyDerivationFunc pkix.AlgorithmIdentifier
	EncryptionScheme  pkix.AlgorithmIdentifier
}

func parseKeyDerivationFunc(keyDerivationFunc pkix.AlgorithmIdentifier) (KDFParameters, error) {
	oid := keyDerivationFunc.Algorithm.String()
	newParams, ok := kdfs[oid]
	if !ok {
		return nil, fmt.Errorf("pkcs8: unsupported KDF (OID: %s)", oid)
	}
	params := newParams()
	_, err := asn1.Unmarshal(keyDerivationFunc.Parameters.FullBytes, params)
	if err != nil {
		return nil, errors.New("pkcs8: invalid KDF parameters")
	}
	return params, nil
}

func parseEncryptionScheme(encryptionScheme *pkix.AlgorithmIdentifier) (Cipher, error) {
	oid := encryptionScheme.Algorithm.String()
	newCipher, ok := ciphers[oid]
	if !ok {
		return nil, fmt.Errorf("pkcs8: unsupported cipher (OID: %s)", oid)
	}
	cipher := newCipher()
	return cipher, nil
}

// ParsePrivateKey parses a DER-encoded PKCS#8 private key.
// Password can be nil.
// This is equivalent to ParsePKCS8PrivateKey.
func ParsePrivateKey(der []byte, password []byte) (interface{}, KDFParameters, error) {
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

	if !privKey.EncryptionAlgorithm.Algorithm.Equal(oidPBES2) {
		return nil, nil, errors.New("pkcs8: only PBES2 supported")
	}

	var params pbes2Params
	if _, err := asn1.Unmarshal(privKey.EncryptionAlgorithm.Parameters.FullBytes, &params); err != nil {
		return nil, nil, errors.New("pkcs8: invalid PBES2 parameters")
	}

	cipher, err := parseEncryptionScheme(&params.EncryptionScheme)
	if err != nil {
		return nil, nil, err
	}

	kdfParams, err := parseKeyDerivationFunc(params.KeyDerivationFunc)
	if err != nil {
		return nil, nil, err
	}

	keySize := cipher.KeySize()
	symkey, err := kdfParams.DeriveKey(password, keySize)
	if err != nil {
		return nil, nil, err
	}

	encryptedKey := privKey.EncryptedData
	decryptedKey, err := cipher.Decrypt(symkey, &params.EncryptionScheme.Parameters, encryptedKey)
	if err != nil {
		return nil, nil, err
	}

	key, err := smx509.ParsePKCS8PrivateKey(decryptedKey)
	if err != nil {
		return nil, nil, errors.New("pkcs8: incorrect password")
	}
	return key, kdfParams, nil
}

// MarshalPrivateKey encodes a private key into DER-encoded PKCS#8 with the given options.
// Password can be nil.
func MarshalPrivateKey(priv interface{}, password []byte, opts *Opts) ([]byte, error) {
	if len(password) == 0 {
		return smx509.MarshalPKCS8PrivateKey(priv)
	}

	if opts == nil {
		opts = DefaultOpts
	}

	// Convert private key into PKCS8 format
	pkey, err := smx509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return nil, err
	}

	encAlg := opts.Cipher
	salt := make([]byte, opts.KDFOpts.GetSaltSize())
	_, err = rand.Read(salt)
	if err != nil {
		return nil, err
	}

	key, kdfParams, err := opts.KDFOpts.DeriveKey(password, salt, encAlg.KeySize())
	if err != nil {
		return nil, err
	}

	encryptionScheme, encryptedKey, err := encAlg.Encrypt(key, pkey)
	if err != nil {
		return nil, err
	}

	marshalledParams, err := asn1.Marshal(kdfParams)
	if err != nil {
		return nil, err
	}
	keyDerivationFunc := pkix.AlgorithmIdentifier{
		Algorithm:  opts.KDFOpts.OID(),
		Parameters: asn1.RawValue{FullBytes: marshalledParams},
	}

	encryptionAlgorithmParams := pbes2Params{
		EncryptionScheme:  *encryptionScheme,
		KeyDerivationFunc: keyDerivationFunc,
	}
	marshalledEncryptionAlgorithmParams, err := asn1.Marshal(encryptionAlgorithmParams)
	if err != nil {
		return nil, err
	}
	encryptionAlgorithm := pkix.AlgorithmIdentifier{
		Algorithm:  oidPBES2,
		Parameters: asn1.RawValue{FullBytes: marshalledEncryptionAlgorithmParams},
	}

	encryptedPkey := encryptedPrivateKeyInfo{
		EncryptionAlgorithm: encryptionAlgorithm,
		EncryptedData:       encryptedKey,
	}

	return asn1.Marshal(encryptedPkey)
}

// ParsePKCS8PrivateKey parses encrypted/unencrypted private keys in PKCS#8 format.
// To parse encrypted private keys, a password of []byte type should be provided to the function as the second parameter.
func ParsePKCS8PrivateKey(der []byte, v ...[]byte) (interface{}, error) {
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

// ParsePKCS8PrivateKeySM2 parses encrypted/unencrypted private keys in PKCS#8 format.
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

// ConvertPrivateKeyToPKCS8 converts the private key into PKCS#8 format.
// To encrypt the private key, the password of []byte type should be provided as the second parameter.
//
// The only supported key types are RSA and ECDSA (*rsa.PrivateKey or *ecdsa.PrivateKey for priv)
func ConvertPrivateKeyToPKCS8(priv interface{}, v ...[]byte) ([]byte, error) {
	var password []byte
	if len(v) > 0 {
		password = v[0]
	}
	return MarshalPrivateKey(priv, password, nil)
}
