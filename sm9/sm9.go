// Package sm9 implements ShangMi(SM) sm9 digital signature, encryption and key exchange algorithms.
package sm9

import (
	"crypto"
	goSubtle "crypto/subtle"
	"errors"
	"io"
	"math/big"

	"github.com/emmansun/gmsm/internal/sm9"
	"github.com/emmansun/gmsm/sm3"
	"golang.org/x/crypto/cryptobyte"
	"golang.org/x/crypto/cryptobyte/asn1"
)

// SM9 ASN.1 format reference: Information security technology - SM9 cryptographic algorithm application specification
type encryptType byte

const (
	ENC_TYPE_XOR encryptType = 0
	ENC_TYPE_ECB encryptType = 1
	ENC_TYPE_CBC encryptType = 2
	ENC_TYPE_OFB encryptType = 4
	ENC_TYPE_CFB encryptType = 8
)

// Sign signs a hash (which should be the result of hashing a larger message)
// using the user dsa key. It returns the signature as a pair of h and s.
// Please use SignASN1 instead.
//
// The signature is randomized. Most applications should use [crypto/rand.Reader]
// as rand. Note that the returned signature does not depend deterministically on
// the bytes read from rand, and may change between calls and/or between versions.
func Sign(rand io.Reader, priv *SignPrivateKey, hash []byte) (*big.Int, []byte, error) {
	h, s, err := priv.internal.Sign(rand, hash, nil)
	if err != nil {
		return nil, nil, err
	}
	return new(big.Int).SetBytes(h), s, nil

}

// Sign signs digest with user's DSA key, reading randomness from rand. The opts argument
// is not currently used but, in keeping with the crypto.Signer interface.
// The result is SM9Signature ASN.1 format.
//
// The signature is randomized. Most applications should use [crypto/rand.Reader]
// as rand. Note that the returned signature does not depend deterministically on
// the bytes read from rand, and may change between calls and/or between versions.
func (priv *SignPrivateKey) Sign(rand io.Reader, hash []byte, opts crypto.SignerOpts) ([]byte, error) {
	h, s, err := priv.internal.Sign(rand, hash, opts)
	if err != nil {
		return nil, err
	}
	return encodeSignature(h, s)
}

// SignASN1 signs a hash (which should be the result of hashing a larger message)
// using the private key, priv. It returns the ASN.1 encoded signature of type SM9Signature.
//
// The signature is randomized. Most applications should use [crypto/rand.Reader]
// as rand. Note that the returned signature does not depend deterministically on
// the bytes read from rand, and may change between calls and/or between versions.
func SignASN1(rand io.Reader, priv *SignPrivateKey, hash []byte) ([]byte, error) {
	return priv.Sign(rand, hash, nil)
}

// Verify verifies the signature in h, s of hash using the master dsa public key and user id, uid and hid.
// Its return value records whether the signature is valid. Please use VerifyASN1 instead.
func Verify(pub *SignMasterPublicKey, uid []byte, hid byte, hash []byte, h *big.Int, s []byte) bool {
	if h.Sign() <= 0 {
		return false
	}
	return pub.internal.Verify(uid, hid, hash, h.Bytes(), s)
}

func encodeSignature(h, s []byte) ([]byte, error) {
	var b cryptobyte.Builder
	b.AddASN1(asn1.SEQUENCE, func(b *cryptobyte.Builder) {
		b.AddASN1OctetString(h)
		b.AddASN1BitString(s)
	})
	return b.Bytes()
}

func parseSignature(sig []byte) ([]byte, []byte, error) {
	var (
		hBytes []byte
		sBytes []byte
		inner  cryptobyte.String
	)
	input := cryptobyte.String(sig)
	if !input.ReadASN1(&inner, asn1.SEQUENCE) ||
		!input.Empty() ||
		!inner.ReadASN1Bytes(&hBytes, asn1.OCTET_STRING) ||
		!inner.ReadASN1BitStringAsBytes(&sBytes) ||
		!inner.Empty() {
		return nil, nil, errors.New("invalid ASN.1")
	}
	if sBytes[0] != 4 {
		return nil, nil, errors.New("sm9: invalid point format")
	}
	return hBytes, sBytes, nil
}

// VerifyASN1 verifies the ASN.1 encoded signature of type SM9Signature, sig, of hash using the
// public key, pub. Its return value records whether the signature is valid.
func VerifyASN1(pub *SignMasterPublicKey, uid []byte, hid byte, hash, sig []byte) bool {
	h, s, err := parseSignature(sig)
	if err != nil {
		return false
	}
	return pub.internal.Verify(uid, hid, hash, h, s)
}

// Verify verifies the ASN.1 encoded signature, sig, of hash using the
// public key, pub. Its return value records whether the signature is valid.
func (pub *SignMasterPublicKey) Verify(uid []byte, hid byte, hash, sig []byte) bool {
	return VerifyASN1(pub, uid, hid, hash, sig)
}

// WrapKey generates and wraps key with reciever's uid and system hid, returns generated key and cipher.
//
// The rand parameter is used as a source of entropy to ensure that
// calls this function twice doesn't result in the same key.
// Most applications should use [crypto/rand.Reader] as random.
func WrapKey(rand io.Reader, pub *EncryptMasterPublicKey, uid []byte, hid byte, kLen int) ([]byte, []byte, error) {
	return pub.internal.WrapKey(rand, uid, hid, kLen)
}

// WrapKey wraps key and converts the cipher as ASN1 format, SM9PublicKey1 definition.
//
// The rand parameter is used as a source of entropy to ensure that
// calls this function twice doesn't result in the same key.
// Most applications should use [crypto/rand.Reader] as random.
func (pub *EncryptMasterPublicKey) WrapKey(rand io.Reader, uid []byte, hid byte, kLen int) ([]byte, []byte, error) {
	key, cipher, err := WrapKey(rand, pub, uid, hid, kLen)
	if err != nil {
		return nil, nil, err
	}
	var b cryptobyte.Builder
	b.AddASN1BitString(cipher)
	cipherASN1, err := b.Bytes()

	return key, cipherASN1, err
}

// WrapKeyASN1 wraps key and converts the result of SM9KeyPackage as ASN1 format. according
// SM9 cryptographic algorithm application specification, SM9KeyPackage defnition.
//
// The rand parameter is used as a source of entropy to ensure that
// calls this function twice doesn't result in the same key.
// Most applications should use [crypto/rand.Reader] as random.
func (pub *EncryptMasterPublicKey) WrapKeyASN1(rand io.Reader, uid []byte, hid byte, kLen int) ([]byte, error) {
	key, cipher, err := WrapKey(rand, pub, uid, hid, kLen)
	if err != nil {
		return nil, err
	}
	var b cryptobyte.Builder
	b.AddASN1(asn1.SEQUENCE, func(b *cryptobyte.Builder) {
		b.AddASN1OctetString(key)
		b.AddASN1BitString(cipher)
	})
	return b.Bytes()
}

// UnmarshalSM9KeyPackage is an utility to unmarshal SM9KeyPackage
func UnmarshalSM9KeyPackage(der []byte) (key []byte, cipher []byte, err error) {
	input := cryptobyte.String(der)
	var (
		inner cryptobyte.String
	)
	if !input.ReadASN1(&inner, asn1.SEQUENCE) ||
		!input.Empty() ||
		!inner.ReadASN1Bytes(&key, asn1.OCTET_STRING) ||
		!inner.ReadASN1BitStringAsBytes(&cipher) ||
		!inner.Empty() {
		return nil, nil, errors.New("sm9: invalid SM9KeyPackage asn.1 data")
	}
	return
}

// ErrDecryption represents a failure to decrypt a message.
// It is deliberately vague to avoid adaptive attacks.
var ErrDecryption = errors.New("sm9: decryption error")

// ErrEmptyPlaintext represents a failure to encrypt an empty message.
var ErrEmptyPlaintext = errors.New("sm9: empty plaintext")

// UnwrapKey unwraps key from cipher, user id and aligned key length
func UnwrapKey(priv *EncryptPrivateKey, uid, cipher []byte, kLen int) ([]byte, error) {
	return priv.internal.UnwrapKey(uid, cipher, kLen)
}

// UnwrapKey unwraps key from cipherDer, user id and aligned key length.
// cipherDer is SM9PublicKey1 format according SM9 cryptographic algorithm application specification.
func (priv *EncryptPrivateKey) UnwrapKey(uid, cipherDer []byte, kLen int) ([]byte, error) {
	var bytes []byte
	input := cryptobyte.String(cipherDer)
	if !input.ReadASN1BitStringAsBytes(&bytes) || !input.Empty() {
		return nil, ErrDecryption
	}
	return UnwrapKey(priv, uid, bytes, kLen)
}

// Encrypt encrypts plaintext, returns ciphertext with format C1||C3||C2.
func Encrypt(rand io.Reader, pub *EncryptMasterPublicKey, uid []byte, hid byte, plaintext []byte, opts EncrypterOpts) ([]byte, error) {
	c1, c2, c3, err := encrypt(rand, pub, uid, hid, plaintext, opts)
	if err != nil {
		return nil, err
	}
	ciphertext := append(c1[1:], c3...)
	ciphertext = append(ciphertext, c2...)
	return ciphertext, nil
}

func encrypt(rand io.Reader, pub *EncryptMasterPublicKey, uid []byte, hid byte, plaintext []byte, opts EncrypterOpts) (c1, c2, c3 []byte, err error) {
	if opts == nil {
		opts = DefaultEncrypterOpts
	}
	if len(plaintext) == 0 {
		return nil, nil, nil, ErrEmptyPlaintext
	}
	key1Len := opts.GetKeySize(plaintext)
	key, c1, err := WrapKey(rand, pub, uid, hid, key1Len+sm3.Size)
	if err != nil {
		return nil, nil, nil, err
	}
	c2, err = opts.Encrypt(rand, key[:key1Len], plaintext)
	if err != nil {
		return nil, nil, nil, err
	}

	hash := sm3.New()
	hash.Write(c2)
	hash.Write(key[key1Len:])
	c3 = hash.Sum(nil)

	return
}

// EncryptASN1 encrypts plaintext and returns ciphertext with ASN.1 format according
// SM9 cryptographic algorithm application specification, SM9Cipher definition.
func EncryptASN1(rand io.Reader, pub *EncryptMasterPublicKey, uid []byte, hid byte, plaintext []byte, opts EncrypterOpts) ([]byte, error) {
	return pub.Encrypt(rand, uid, hid, plaintext, opts)
}

// Encrypt encrypts plaintext and returns ciphertext with ASN.1 format according
// SM9 cryptographic algorithm application specification, SM9Cipher definition.
func (pub *EncryptMasterPublicKey) Encrypt(rand io.Reader, uid []byte, hid byte, plaintext []byte, opts EncrypterOpts) ([]byte, error) {
	if opts == nil {
		opts = DefaultEncrypterOpts
	}
	c1, c2, c3, err := encrypt(rand, pub, uid, hid, plaintext, opts)
	if err != nil {
		return nil, err
	}

	var b cryptobyte.Builder
	b.AddASN1(asn1.SEQUENCE, func(b *cryptobyte.Builder) {
		b.AddASN1Int64(int64(opts.GetEncryptType()))
		b.AddASN1BitString(c1)
		b.AddASN1OctetString(c3)
		b.AddASN1OctetString(c2)
	})
	return b.Bytes()
}

// Decrypt decrypts chipher, the ciphertext should be with format C1||C3||C2
func Decrypt(priv *EncryptPrivateKey, uid, ciphertext []byte, opts EncrypterOpts) ([]byte, error) {
	if opts == nil {
		opts = DefaultEncrypterOpts
	}

	c1 := ciphertext[:64]
	c3c2 := ciphertext[64:]
	c3 := c3c2[:sm3.Size]
	c2 := c3c2[sm3.Size:]
	return decrypt(priv, uid, c1, c2, c3, opts)
}

func decrypt(priv *EncryptPrivateKey, uid, c1, c2, c3 []byte, opts EncrypterOpts) ([]byte, error) {
	key1Len := opts.GetKeySize(c2)
	key, err := UnwrapKey(priv, uid, c1, key1Len+sm3.Size)
	if err != nil {
		return nil, err
	}
	_ = key[key1Len] // bounds check elimination hint

	hash := sm3.New()
	hash.Write(c2)
	hash.Write(key[key1Len:])
	c32 := hash.Sum(nil)

	if goSubtle.ConstantTimeCompare(c3, c32) != 1 {
		return nil, ErrDecryption
	}

	return opts.Decrypt(key[:key1Len], c2)
}

// DecryptASN1 decrypts chipher, the ciphertext should be with ASN.1 format according
// SM9 cryptographic algorithm application specification, SM9Cipher definition.
func DecryptASN1(priv *EncryptPrivateKey, uid, ciphertext []byte) ([]byte, error) {
	if len(ciphertext) <= 32+65 {
		return nil, errors.New("sm9: ciphertext too short")
	}
	var (
		encType int
		c3Bytes []byte
		c1Bytes []byte
		c2Bytes []byte
		inner   cryptobyte.String
	)
	input := cryptobyte.String(ciphertext)
	if !input.ReadASN1(&inner, asn1.SEQUENCE) ||
		!input.Empty() ||
		!inner.ReadASN1Integer(&encType) ||
		!inner.ReadASN1BitStringAsBytes(&c1Bytes) ||
		!inner.ReadASN1Bytes(&c3Bytes, asn1.OCTET_STRING) ||
		!inner.ReadASN1Bytes(&c2Bytes, asn1.OCTET_STRING) ||
		!inner.Empty() {
		return nil, errors.New("sm9: invalid ciphertext asn.1 data")
	}
	// We just make assumption block cipher is SM4 and padding scheme is pkcs7
	opts := shangMiEncrypterOpts(encryptType(encType))
	if opts == nil {
		return nil, ErrDecryption
	}
	return decrypt(priv, uid, c1Bytes, c2Bytes, c3Bytes, opts)
}

type DecrypterOptsWithUID struct {
	EncrypterOpts
	UID []byte
}

// NewDecrypterOptsWithUID creates a new DecrypterOptsWithUID instance with the provided
// EncrypterOpts and UID. The UID must not be empty, otherwise an error is returned.
func NewDecrypterOptsWithUID(opts EncrypterOpts, uid []byte) (*DecrypterOptsWithUID, error) {
	if len(uid) == 0 {
		return nil, errors.New("sm9: invalid uid")
	}
	return &DecrypterOptsWithUID{EncrypterOpts: opts, UID: uid}, nil
}

// Decrypt decrypts the given ciphertext using the provided EncryptPrivateKey.
// The decryption process depends on the type of the opts parameter:
// - If opts is of type []byte, it uses DecryptASN1 to decrypt the ciphertext.
// - If opts is of type *DecrypterOptsWithUID, it first checks if the ciphertext
//   is a valid ASN.1 sequence. If it is not, and EncrypterOpts is nil, it returns
//   an error indicating invalid ASN.1 data. Otherwise, it uses the Decrypt function
//   with the provided UID and EncrypterOpts to decrypt the ciphertext. If the
//   ciphertext is a valid ASN.1 sequence, it uses DecryptASN1 with the UID to
//   decrypt the ciphertext.
// If opts is of an unsupported type, it returns an error indicating invalid decrypter options.
func (priv *EncryptPrivateKey) Decrypt(rand io.Reader, ciphertext []byte, opts crypto.DecrypterOpts) ([]byte, error) {
	switch xx := opts.(type) {
	case []byte:
		return DecryptASN1(priv, xx, ciphertext)
	case *DecrypterOptsWithUID:
		var inner cryptobyte.String
		input := cryptobyte.String(ciphertext)
		if !input.ReadASN1(&inner, asn1.SEQUENCE) || !input.Empty() {
			if xx.EncrypterOpts == nil {
				return nil, errors.New("sm9: invalid ciphertext asn.1 data")
			}
			return Decrypt(priv, xx.UID, ciphertext, xx.EncrypterOpts)
		} else {
			return DecryptASN1(priv, xx.UID, ciphertext)
		}
	}
	return nil, errors.New("sm9: invalid decrypter options")
}

// DecryptASN1 decrypts chipher, the ciphertext should be with ASN.1 format according
// SM9 cryptographic algorithm application specification, SM9Cipher definition.
// @Deprecated: Use Decrypt instead.
func (priv *EncryptPrivateKey) DecryptASN1(uid, ciphertext []byte) ([]byte, error) {
	return DecryptASN1(priv, uid, ciphertext)
}

// KeyExchange defines an interface for key exchange protocols.
// It provides methods for initializing, responding, and confirming key exchanges.
//
// InitKeyExchange initializes the key exchange process.
// It takes a random number generator and a byte identifier as input, and returns
// the initial data for the key exchange and an error, if any.
//
// RespondKeyExchange responds to an initiated key exchange.
// It takes a random number generator, a byte identifier, and the peer's initial data
// as input, and returns the response data, additional data for confirmation, and an error, if any.
//
// ConfirmResponder confirms the key exchange from the responder's side.
// It takes the responder's response data and additional data as input, and returns
// the confirmation data and an error, if any.
//
// ConfirmInitiator confirms the key exchange from the initiator's side.
// It takes the peer's confirmation data as input, and returns the final confirmation data
// and an error, if any.
// KeyExchange defines an interface for key exchange operations.
// It provides methods to initialize, respond, and confirm key exchanges,
// as well as a method to destroy the key exchange instance.
type KeyExchange interface {
	// Destroy cleans up any resources associated with the key exchange instance.
	Destroy()

	// InitKeyExchange initializes the key exchange process.
	// It takes a random number generator and a byte identifier as input,
	// and returns the initial data for the key exchange or an error.
	InitKeyExchange(rand io.Reader, hid byte) ([]byte, error)

	// RespondKeyExchange responds to an initiated key exchange.
	// It takes a random number generator, a byte identifier, and the peer's initial data as input,
	// and returns the response data, additional data, or an error.
	RespondKeyExchange(rand io.Reader, hid byte, peerData []byte) ([]byte, []byte, error)

	// ConfirmResponder confirms the responder's part of the key exchange.
	// It takes the responder's response data and additional data as input,
	// and returns the confirmation data or an error.
	ConfirmResponder(rB, sB []byte) ([]byte, []byte, error)

	// ConfirmInitiator confirms the initiator's part of the key exchange.
	// It takes the peer's data as input and returns the confirmation data or an error.
	ConfirmInitiator(peerData []byte) ([]byte, error)
}

// keyExchange represents key exchange struct, include internal stat in whole key exchange flow.
// Initiator's flow will be: NewKeyExchange -> InitKeyExchange -> transmission -> ConfirmResponder
// Responder's flow will be: NewKeyExchange -> waiting ... -> RepondKeyExchange -> transmission -> ConfirmInitiator
type keyExchange struct {
	ke *sm9.KeyExchange
}

// NewKeyExchange initializes a new key exchange process using the provided user IDs and key length.
// It returns a pointer to a keyExchange struct which contains the key exchange instance.
func (priv *EncryptPrivateKey) NewKeyExchange(uid, peerUID []byte, keyLen int, genSignature bool) *keyExchange {
	return &keyExchange{ke: priv.internal.NewKeyExchange(uid, peerUID, keyLen, genSignature)}
}

// Destroy securely wipes the key exchange data from memory.
func (ke *keyExchange) Destroy() {
	ke.ke.Destroy()
}

// InitKeyExchange generates random with responder uid, for initiator's step A1-A4
func (ke *keyExchange) InitKeyExchange(rand io.Reader, hid byte) ([]byte, error) {
	return ke.ke.InitKeyExchange(rand, hid)
}

// RespondKeyExchange when responder receive rA, for responder's step B1-B7
func (ke *keyExchange) RespondKeyExchange(rand io.Reader, hid byte, peerData []byte) ([]byte, []byte, error) {
	return ke.ke.RespondKeyExchange(rand, hid, peerData)
}

// ConfirmResponder for initiator's step A5-A7
func (ke *keyExchange) ConfirmResponder(rB, sB []byte) ([]byte, []byte, error) {
	return ke.ke.ConfirmResponder(rB, sB)
}

// ConfirmInitiator for responder's step B8
func (ke *keyExchange) ConfirmInitiator(peerData []byte) ([]byte, error) {
	return ke.ke.ConfirmInitiator(peerData)
}
