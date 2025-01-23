// Package cfca supports part of CFCA SADK's functions, provides interoperability with CFCA SADK.
package cfca

import (
	"encoding/asn1"
	"errors"
	"fmt"
	"math/big"

	"github.com/emmansun/gmsm/pkcs"
	"github.com/emmansun/gmsm/pkcs7"
	"github.com/emmansun/gmsm/sm2"
	"github.com/emmansun/gmsm/smx509"
)

// cfcaKeyPairData represents a key pair data structure used
// in CFCA (China Financial Certification Authority)
// for both parsing and marshaling SM2 keys and certificates.
type cfcaKeyPairData struct {
	Version      int `asn1:"default:1"`
	EncryptedKey keyData
	Certificate  certData
}

// Encrypted private key data
type keyData struct {
	ContentType      asn1.ObjectIdentifier
	Algorithm        asn1.ObjectIdentifier
	EncryptedContent asn1.RawValue
}

// Corresponding certificate
type certData struct {
	ContentType asn1.ObjectIdentifier
	Content     asn1.RawContent
}

var (
	oidSM2Data = pkcs7.SM2OIDData
	oidSM4     = pkcs.SM4.OID()
	oidSM4CBC  = pkcs.SM4CBC.OID()
)

// ParseSM2 parses the der data, returns private key and related certificate, it's CFCA private structure.
// This method is corresponding to CFCA SADK's cfca.sadk.asn1.pkcs.load.
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
	pk, err := DecryptBySM4CBC(keys.EncryptedKey.EncryptedContent.Bytes, password)
	if err != nil {
		return nil, nil, fmt.Errorf("cfca: failed to decrypt by SM4-CBC, please ensure the password is correct: %v", err)
	}
	prvKey, err := sm2.NewPrivateKeyFromInt(new(big.Int).SetBytes(pk))
	if err != nil {
		return nil, nil, err
	}
	cert, err := smx509.ParseCertificate(keys.Certificate.Content)
	if err != nil {
		return nil, nil, err
	}

	if !prvKey.PublicKey.Equal(cert.PublicKey) {
		return nil, nil, errors.New("cfca: public key and private key do not match")
	}
	return prvKey, cert, nil
}

// MarshalSM2 encodes sm2 private key and related certificate to cfca defined format.
// This method is corresponding to CFCA SADK's cfca.sadk.asn1.pkcs.CombineSM2Data.
func MarshalSM2(password []byte, key *sm2.PrivateKey, cert *smx509.Certificate) ([]byte, error) {
	var err error
	var ciphertext []byte
	if ciphertext, err = EncryptBySM4CBC(key.D.Bytes(), password); err != nil {
		return nil, err
	}
	if ciphertext, err = asn1.Marshal(ciphertext); err != nil {
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
