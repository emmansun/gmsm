package sm2

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/asn1"
	"errors"
	"fmt"
	"io"
	"math/big"

	"github.com/emmansun/gmsm/cipher"
	"github.com/emmansun/gmsm/sm4"
	"golang.org/x/crypto/cryptobyte"
	cryptobyte_asn1 "golang.org/x/crypto/cryptobyte/asn1"
)

var (
	oidSM4    = asn1.ObjectIdentifier{1, 2, 156, 10197, 1, 104}
	oidSM4ECB = asn1.ObjectIdentifier{1, 2, 156, 10197, 1, 104, 1}
)

// MarshalEnvelopedPrivateKey, returns sm2 key pair protected data with ASN.1 format:
//
// SM2EnvelopedKey ::= SEQUENCE {
//   symAlgID                AlgorithmIdentifier,
//   sysmEncryptedKey        SM2Cipher,
//   sm2PublicKey            SM2PublicKey,
//   sm2EncryptedPrivateKey  BIT STRING,
// }
//
// This implementation follows GB/T 35276-2017, uses SM4 cipher to encrypt sm2 private key.
func MarshalEnvelopedPrivateKey(rand io.Reader, pub *ecdsa.PublicKey, tobeEnveloped *PrivateKey) ([]byte, error) {
	// encrypt sm2 private key
	size := (tobeEnveloped.Curve.Params().N.BitLen() + 7) / 8
	if tobeEnveloped.D.BitLen() > size*8 {
		return nil, errors.New("sm2: invalid private key")
	}
	plaintext := tobeEnveloped.D.FillBytes(make([]byte, size))

	key := make([]byte, sm4.BlockSize)
	if _, err := io.ReadFull(rand, key); err != nil {
		return nil, err
	}
	block, err := sm4.NewCipher(key)
	if err != nil {
		return nil, err
	}
	mode := cipher.NewECBEncrypter(block)

	encryptedPrivateKey := make([]byte, len(plaintext))
	mode.CryptBlocks(encryptedPrivateKey, plaintext)

	// encrypt the symmetric key
	encryptedKey, err := EncryptASN1(rand, pub, key)
	if err != nil {
		return nil, err
	}

	// marshal the result
	var b cryptobyte.Builder
	b.AddASN1(cryptobyte_asn1.SEQUENCE, func(b *cryptobyte.Builder) {
		b.AddASN1ObjectIdentifier(oidSM4) // use oidSM4ECB?
		b.AddBytes(encryptedKey)
		b.AddASN1BitString(elliptic.Marshal(tobeEnveloped.Curve, tobeEnveloped.X, tobeEnveloped.Y))
		b.AddASN1BitString(encryptedPrivateKey)
	})
	return b.Bytes()
}

// ParseEnvelopedPrivateKey, parses and decrypts the enveloped SM2 private key.
// This methed just supports SM4 cipher now.
func ParseEnvelopedPrivateKey(priv *PrivateKey, enveloped []byte) (*PrivateKey, error) {
	// unmarshal the asn.1 data
	var (
		symAlgId                 asn1.ObjectIdentifier
		encryptedPrivateKey, pub asn1.BitString
		inner, symEncryptedKey   cryptobyte.String
	)
	input := cryptobyte.String(enveloped)
	if !input.ReadASN1(&inner, cryptobyte_asn1.SEQUENCE) ||
		!input.Empty() ||
		!inner.ReadASN1ObjectIdentifier(&symAlgId) ||
		!inner.ReadASN1Element(&symEncryptedKey, cryptobyte_asn1.SEQUENCE) ||
		!inner.ReadASN1BitString(&pub) ||
		!inner.ReadASN1BitString(&encryptedPrivateKey) ||
		!inner.Empty() {
		return nil, errors.New("sm2: invalid asn1 format enveloped key")
	}

	if !(symAlgId.Equal(oidSM4) || symAlgId.Equal(oidSM4ECB)) {
		return nil, fmt.Errorf("sm2: unsupported symmetric cipher <%v>", symAlgId)
	}

	// parse public key
	x, y := elliptic.Unmarshal(P256(), pub.RightAlign())
	if x == nil || y == nil {
		return nil, errors.New("sm2: invald public key in enveloped data")
	}

	// decrypt symmetric cipher key
	key, err := priv.Decrypt(rand.Reader, symEncryptedKey, nil)
	if err != nil {
		return nil, err
	}

	// decrypt sm2 private key
	block, err := sm4.NewCipher(key)
	if err != nil {
		return nil, err
	}
	mode := cipher.NewECBDecrypter(block)
	bytes := encryptedPrivateKey.RightAlign()
	plaintext := make([]byte, len(bytes))
	mode.CryptBlocks(plaintext, bytes)
	sm2Key := new(PrivateKey)
	sm2Key.D = new(big.Int).SetBytes(plaintext)
	sm2Key.Curve = P256()
	sm2Key.X, sm2Key.Y = sm2Key.ScalarBaseMult(plaintext)

	if sm2Key.X.Cmp(x) != 0 || sm2Key.Y.Cmp(y) != 0 {
		return nil, errors.New("sm2: mismatch key pair in enveloped data")
	}

	return sm2Key, nil
}
