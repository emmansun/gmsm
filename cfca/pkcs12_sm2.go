// Package cfca handles cfca issued key and certificate
package cfca

import (
	"crypto/cipher"
	"encoding/asn1"
	"errors"
	"fmt"
	"math/big"

	"github.com/emmansun/gmsm/padding"
	"github.com/emmansun/gmsm/pkcs"
	"github.com/emmansun/gmsm/sm2"
	"github.com/emmansun/gmsm/sm3"
	"github.com/emmansun/gmsm/sm4"
	"github.com/emmansun/gmsm/smx509"
)

// CFCA私有格式，在SADK中把它定义为PKCS12_SM2

type cfcaKeyPairData struct {
	Version      int `asn1:"default:1"`
	EncryptedKey keyData
	Certificate  certData
}

// 被加密的私钥数据
type keyData struct {
	ContentType      asn1.ObjectIdentifier
	Algorithm        asn1.ObjectIdentifier
	EncryptedContent asn1.RawValue
}

// 对应的证书
type certData struct {
	ContentType asn1.ObjectIdentifier
	Content     asn1.RawContent
}

var (
	oidSM2Data = asn1.ObjectIdentifier{1, 2, 156, 10197, 6, 1, 4, 2, 1}
	oidSM4     = asn1.ObjectIdentifier{1, 2, 156, 10197, 1, 104} // SADK中认为这就是SM4_CBC，不知道是不是历史原因
	oidSM4CBC  = asn1.ObjectIdentifier{1, 2, 156, 10197, 1, 104, 2}
)

// ParseSM2 parses the der data, returns private key and related certificate, it's CFCA private structure.
func ParseSM2(password, data []byte) (*sm2.PrivateKey, *smx509.Certificate, error) {
	var keys cfcaKeyPairData
	if _, err := asn1.Unmarshal(data, &keys); err != nil {
		return nil, nil, err
	}
	if !keys.Certificate.ContentType.Equal(oidSM2Data) {
		return nil, nil, fmt.Errorf("cfca: unsupported content type oid <%v>", keys.Certificate.ContentType)
	}
	if !keys.EncryptedKey.ContentType.Equal(oidSM2Data) {
		return nil, nil, fmt.Errorf("cfca: unsupported content type oid <%v>", keys.EncryptedKey.ContentType)
	}
	if !keys.EncryptedKey.Algorithm.Equal(oidSM4) && !keys.EncryptedKey.Algorithm.Equal(oidSM4CBC) {
		return nil, nil, fmt.Errorf("cfca: unsupported algorithm <%v>", keys.EncryptedKey.Algorithm)
	}
	ivkey := sm3.Kdf(password, 32)
	marshalledIV, err := asn1.Marshal(ivkey[:16])
	if err != nil {
		return nil, nil, err
	}
	pk, err := pkcs.SM4CBC.Decrypt(ivkey[16:], &asn1.RawValue{FullBytes: marshalledIV}, keys.EncryptedKey.EncryptedContent.Bytes)
	if err != nil {
		return nil, nil, err
	}
	d := new(big.Int).SetBytes(pk) // here we do NOT check if the d is in (0, N) or not
	// Create private key from *big.Int
	prvKey := new(sm2.PrivateKey)
	prvKey.Curve = sm2.P256()
	prvKey.D = d
	prvKey.PublicKey.X, prvKey.PublicKey.Y = prvKey.ScalarBaseMult(prvKey.D.Bytes())

	cert, err := smx509.ParseCertificate(keys.Certificate.Content)
	if err != nil {
		return nil, nil, err
	}

	if !prvKey.PublicKey.Equal(cert.PublicKey) {
		return nil, nil, errors.New("cfca: public key and private key do not match")
	}
	return prvKey, cert, nil
}

// MarshalSM2 encodes sm2 private key and related certificate to cfca defined format
func MarshalSM2(password []byte, key *sm2.PrivateKey, cert *smx509.Certificate) ([]byte, error) {
	if len(password) == 0 {
		return nil, errors.New("cfca: invalid password")
	}
	ivkey := sm3.Kdf(password, 32)
	block, err := sm4.NewCipher(ivkey[16:])
	if err != nil {
		return nil, err
	}
	mode := cipher.NewCBCEncrypter(block, ivkey[:16])
	pkcs7 := padding.NewPKCS7Padding(uint(block.BlockSize()))
	plainText := pkcs7.Pad(key.D.Bytes())
	ciphertext := make([]byte, len(plainText))
	mode.CryptBlocks(ciphertext, plainText)

	ciphertext, err = asn1.Marshal(ciphertext)
	if err != nil {
		return nil, err
	}

	keys := cfcaKeyPairData{
		Version: 1,
		EncryptedKey: keyData{
			ContentType:      oidSM2Data,
			Algorithm:        oidSM4,
			EncryptedContent: asn1.RawValue{FullBytes: ciphertext},
		},
		Certificate: certData{
			ContentType: oidSM2Data,
			Content:     cert.Raw,
		},
	}

	return asn1.Marshal(keys)
}
