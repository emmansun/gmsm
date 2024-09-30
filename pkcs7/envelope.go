package pkcs7

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"

	"github.com/emmansun/gmsm/pkcs"
	"github.com/emmansun/gmsm/sm2"
	"github.com/emmansun/gmsm/smx509"
)

type EnvelopedData struct {
	ed                   envelopedData
	key                  []byte
	contentType          asn1.ObjectIdentifier
	encryptedContentType asn1.ObjectIdentifier
}

type envelopedData struct {
	Version              int
	RecipientInfos       []recipientInfo `asn1:"set"`
	EncryptedContentInfo encryptedContentInfo
}

type recipientInfo struct {
	Version                int
	IssuerAndSerialNumber  issuerAndSerial
	KeyEncryptionAlgorithm pkix.AlgorithmIdentifier
	EncryptedKey           []byte
}

type encryptedContentInfo struct {
	ContentType                asn1.ObjectIdentifier
	ContentEncryptionAlgorithm pkix.AlgorithmIdentifier
	EncryptedContent           asn1.RawValue `asn1:"tag:0,optional"`
}

func (data envelopedData) GetRecipient(cert *smx509.Certificate) *recipientInfo {
	for _, recp := range data.RecipientInfos {
		if isCertMatchForIssuerAndSerial(cert, recp.IssuerAndSerialNumber) {
			return &recp
		}
	}
	return nil
}

// GetRecipients returns the list of recipients (READONLY) for the enveloped data
func (data envelopedData) GetRecipients() ([]IssuerAndSerial, error) {
	var recipients []IssuerAndSerial
	for _, recp := range data.RecipientInfos {
		recipients = append(recipients, newIssuerAndSerial(recp.IssuerAndSerialNumber))
	}
	return recipients, nil
}

func (data envelopedData) GetEncryptedContentInfo() *encryptedContentInfo {
	return &data.EncryptedContentInfo
}

// ErrUnsupportedEncryptionAlgorithm is returned when attempting to encrypt
// content with an unsupported algorithm.
var ErrUnsupportedEncryptionAlgorithm = errors.New("pkcs7: cannot encrypt content: only DES-CBC, AES-CBC, AES-GCM, SM4-CBC and SM4-GCM supported")

// Encrypt creates and returns an envelope data PKCS7 structure with encrypted
// recipient keys for each recipient public key.
//
// # The algorithm used to perform encryption is determined by the argument cipher
//
// TODO(fullsailor): Add support for encrypting content with other algorithms
func Encrypt(cipher pkcs.Cipher, content []byte, recipients []*smx509.Certificate) ([]byte, error) {
	ed, err := NewEnvelopedData(cipher, content)
	if err != nil {
		return nil, err
	}
	for _, recipient := range recipients {
		if err := ed.AddRecipient(recipient, 0, func(cert *smx509.Certificate, key []byte) ([]byte, error) {
			return encryptKey(key, cert, false)
		}); err != nil {
			return nil, err
		}
	}
	return ed.Finish()
}

// EncryptSM creates and returns an envelope data PKCS7 structure with encrypted
// recipient keys for each recipient public key.
// The OIDs use GM/T 0010 - 2012 set and the encrypted key use ASN.1 format.
//
// The algorithm used to perform encryption is determined by the argument cipher
func EncryptSM(cipher pkcs.Cipher, content []byte, recipients []*smx509.Certificate) ([]byte, error) {
	return encryptSM(cipher, content, recipients, false)
}

// EncryptCFCA creates and returns an envelope data PKCS7 structure with encrypted
// recipient keys for each recipient public key.
// The OIDs use GM/T 0010 - 2012 set and the encrypted key use C1C2C3 format and without 0x4 prefix.
//
// The algorithm used to perform encryption is determined by the argument cipher
func EncryptCFCA(cipher pkcs.Cipher, content []byte, recipients []*smx509.Certificate) ([]byte, error) {
	return encryptSM(cipher, content, recipients, true)
}

func encryptSM(cipher pkcs.Cipher, content []byte, recipients []*smx509.Certificate, isLegacyCFCA bool) ([]byte, error) {
	ed, err := NewSM2EnvelopedData(cipher, content)
	if err != nil {
		return nil, err
	}
	for _, recipient := range recipients {
		if err := ed.AddRecipient(recipient, 1, func(cert *smx509.Certificate, key []byte) ([]byte, error) {
			return encryptKey(key, cert, isLegacyCFCA)
		}); err != nil {
			return nil, err
		}
	}
	return ed.Finish()
}

// NewEnvelopedData creates a new EnvelopedData structure with the provided cipher and content.
func NewEnvelopedData(cipher pkcs.Cipher, content []byte) (*EnvelopedData, error) {
	var key []byte
	var err error

	// Create key
	key = make([]byte, cipher.KeySize())
	if _, err = rand.Read(key); err != nil {
		return nil, err
	}

	id, ciphertext, err := cipher.Encrypt(rand.Reader, key, content)
	if err != nil {
		return nil, err
	}
	ed := &EnvelopedData{}
	ed.contentType = OIDEnvelopedData
	ed.encryptedContentType = OIDData
	ed.key = key
	ed.ed = envelopedData{
		Version:              0,
		EncryptedContentInfo: newEncryptedContent(ed.encryptedContentType, id, marshalEncryptedContent(ciphertext)),
	}
	return ed, nil
}

// NewSM2EnvelopedData creates a new EnvelopedData structure with the provided cipher and content.
// The OIDs use GM/T 0010 - 2012 set.
func NewSM2EnvelopedData(cipher pkcs.Cipher, content []byte) (*EnvelopedData, error) {
	var key []byte
	var err error

	// Create key
	key = make([]byte, cipher.KeySize())
	if _, err = rand.Read(key); err != nil {
		return nil, err
	}

	id, ciphertext, err := cipher.Encrypt(rand.Reader, key, content)
	if err != nil {
		return nil, err
	}
	ed := &EnvelopedData{}
	ed.contentType = SM2OIDEnvelopedData
	ed.encryptedContentType = SM2OIDData
	ed.key = key
	ed.ed = envelopedData{
		Version:              1,
		EncryptedContentInfo: newEncryptedContent(ed.encryptedContentType, id, marshalEncryptedContent(ciphertext)),
	}
	return ed, nil
}

// AddRecipient adds a recipient to the EnvelopedData structure.
func (ed *EnvelopedData) AddRecipient(cert *smx509.Certificate, version int, encryptKeyFunc func(cert *smx509.Certificate, key []byte) ([]byte, error)) error {
	encrypted, err := encryptKeyFunc(cert, ed.key)
	if err != nil {
		return err
	}
	ias, err := cert2issuerAndSerial(cert)
	if err != nil {
		return err
	}
	var keyEncryptionAlgorithm asn1.ObjectIdentifier = OIDEncryptionAlgorithmRSA
	if cert.SignatureAlgorithm == smx509.SM2WithSM3 {
		keyEncryptionAlgorithm = OIDKeyEncryptionAlgorithmSM2
	}

	info := recipientInfo{
		Version:               version,
		IssuerAndSerialNumber: ias,
		KeyEncryptionAlgorithm: pkix.AlgorithmIdentifier{
			Algorithm: keyEncryptionAlgorithm,
		},
		EncryptedKey: encrypted,
	}
	ed.ed.RecipientInfos = append(ed.ed.RecipientInfos, info)
	return nil
}

// Finish creates the final PKCS7 structure.
func (ed *EnvelopedData) Finish() ([]byte, error) {
	innerContent, err := asn1.Marshal(ed.ed)
	if err != nil {
		return nil, err
	}

	// Prepare outer payload structure
	wrapper := contentInfo{
		ContentType: ed.contentType,
		Content:     asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 0, IsCompound: true, Bytes: innerContent},
	}
	return asn1.Marshal(wrapper)
}

func newEncryptedContent(contentType asn1.ObjectIdentifier, alg *pkix.AlgorithmIdentifier, ciphertext asn1.RawValue) encryptedContentInfo {
	return encryptedContentInfo{
		ContentType:                contentType,
		ContentEncryptionAlgorithm: *alg,
		EncryptedContent:           ciphertext,
	}
}

func marshalEncryptedContent(content []byte) asn1.RawValue {
	asn1Content, _ := asn1.Marshal(content)
	return asn1.RawValue{Tag: 0, Class: asn1.ClassContextSpecific, Bytes: asn1Content, IsCompound: true}
}

func encryptKey(key []byte, recipient *smx509.Certificate, isCFCA bool) ([]byte, error) {
	if pub, ok := recipient.PublicKey.(*rsa.PublicKey); ok {
		return rsa.EncryptPKCS1v15(rand.Reader, pub, key)
	}
	if pub, ok := recipient.PublicKey.(*ecdsa.PublicKey); ok && pub.Curve == sm2.P256() {
		if isCFCA {
			encryptedKey, err := sm2.Encrypt(rand.Reader, pub, key, sm2.NewPlainEncrypterOpts(sm2.MarshalUncompressed, sm2.C1C2C3))
			if err != nil {
				return nil, err
			}
			return encryptedKey[1:], nil
		} else {
			return sm2.EncryptASN1(rand.Reader, pub, key)
		}
	}
	return nil, errors.New("pkcs7: only supports RSA/SM2 key")
}
