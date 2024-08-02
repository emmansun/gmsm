package sm2

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"fmt"
	"io"

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
//	SM2EnvelopedKey ::= SEQUENCE {
//	  symAlgID                AlgorithmIdentifier,
//	  symEncryptedKey         SM2Cipher,
//	  sm2PublicKey            SM2PublicKey,
//	  sm2EncryptedPrivateKey  BIT STRING,
//	}
//
// This implementation follows GB/T 35276-2017, uses SM4 cipher to encrypt sm2 private key.
// Please note the standard did NOT clarify if the ECB mode requires padding or not.
//
// This function can be used in CSRResponse.encryptedPrivateKey, reference GM/T 0092-2020 
// Specification of certificate request syntax based on SM2 cryptographic algorithm.
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

	symAlgID := pkix.AlgorithmIdentifier{
		Algorithm:  oidSM4ECB,
		Parameters: asn1.NullRawValue,
	}
	symAlgIDBytes, _ := asn1.Marshal(symAlgID)

	// marshal the result
	var b cryptobyte.Builder
	b.AddASN1(cryptobyte_asn1.SEQUENCE, func(b *cryptobyte.Builder) {
		b.AddBytes(symAlgIDBytes)
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
		symAlgId                              pkix.AlgorithmIdentifier
		encryptedPrivateKey, pub              asn1.BitString
		inner, symEncryptedKey, symAlgIdBytes cryptobyte.String
	)
	input := cryptobyte.String(enveloped)
	if !input.ReadASN1(&inner, cryptobyte_asn1.SEQUENCE) ||
		!input.Empty() ||
		!inner.ReadASN1Element(&symAlgIdBytes, cryptobyte_asn1.SEQUENCE) ||
		!inner.ReadASN1Element(&symEncryptedKey, cryptobyte_asn1.SEQUENCE) ||
		!inner.ReadASN1BitString(&pub) ||
		!inner.ReadASN1BitString(&encryptedPrivateKey) ||
		!inner.Empty() {
		return nil, errors.New("sm2: invalid asn1 format enveloped key")
	}

	if _, err := asn1.Unmarshal(symAlgIdBytes, &symAlgId); err != nil {
		return nil, err
	}

	if !(symAlgId.Algorithm.Equal(oidSM4) || symAlgId.Algorithm.Equal(oidSM4ECB)) {
		return nil, fmt.Errorf("sm2: unsupported symmetric cipher <%v>", symAlgId.Algorithm)
	}

	// parse public key
	pubKey, err := NewPublicKey(pub.RightAlign())
	if err != nil {
		return nil, err
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
	// Do we need to check length in order to be compatible with some implementations with padding?
	sm2Key, err := NewPrivateKey(plaintext)
	if err != nil {
		return nil, err
	}
	if !sm2Key.PublicKey.Equal(pubKey) {
		return nil, errors.New("sm2: mismatch key pair in enveloped data")
	}

	return sm2Key, nil
}
