package pkcs7

import (
	"bytes"
	"crypto/rand"
	"crypto/sha1"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"

	"github.com/emmansun/gmsm/pkcs"
	"github.com/emmansun/gmsm/smx509"
	"golang.org/x/crypto/cryptobyte"
	cryptobyte_asn1 "golang.org/x/crypto/cryptobyte/asn1"
)

type EnvelopedData struct {
	ed                   envelopedData
	key                  []byte
	contentType          asn1.ObjectIdentifier
	encryptedContentType asn1.ObjectIdentifier
	session              Session
}

type envelopedData struct {
	Version              int
	RecipientInfos       []recipientInfo `asn1:"set"`
	EncryptedContentInfo encryptedContentInfo
}

type recipientInfo struct {
	Version                int
	IssuerAndSerialNumber  issuerAndSerial `asn1:"optional"`
	SubjectKeyIdentifier   asn1.RawValue   `asn1:"tag:0,optional"`
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
		} else if len(recp.SubjectKeyIdentifier.Bytes) > 0 {
			// This is for the case when the recipient is identified by the SubjectKeyId instead of the IssuerAndSerial
			subjectKeyID := cert.SubjectKeyId
			// SubjectKeyId is optional, so we need to check if it's set before comparing
			if len(subjectKeyID) == 0 {
				var (
					inner cryptobyte.String
					pub   asn1.BitString
				)
				input := cryptobyte.String(cert.RawSubjectPublicKeyInfo)
				if input.ReadASN1(&inner, cryptobyte_asn1.SEQUENCE) &&
					input.Empty() &&
					inner.SkipASN1(cryptobyte_asn1.SEQUENCE) &&
					inner.ReadASN1BitString(&pub) &&
					inner.Empty() {
					h := sha1.Sum(pub.RightAlign())
					subjectKeyID = h[:]
				}
			}

			if len(subjectKeyID) > 0 && bytes.Equal(subjectKeyID, recp.SubjectKeyIdentifier.Bytes) {
				return &recp
			}
		}
	}
	return nil
}

// GetRecipients returns the list of recipients (READONLY) for the enveloped data
func (data envelopedData) GetRecipients() ([]RecipientInfo, error) {
	var recipients []RecipientInfo
	for _, recp := range data.RecipientInfos {
		recipients = append(recipients, newRecipientInfo(recp))
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
			return ed.session.EncryptdDataKey(key, cert, nil)
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
	return encryptSM(cipher, content, recipients, 1, false)
}

// EncryptCFCA creates and returns an envelope data PKCS7 structure with encrypted
// recipient keys for each recipient public key.
// The OIDs use GM/T 0010 - 2012 set and the encrypted key use C1C2C3 format and without 0x4 prefix.
//
// The algorithm used to perform encryption is determined by the argument cipher
func EncryptCFCA(cipher pkcs.Cipher, content []byte, recipients []*smx509.Certificate) ([]byte, error) {
	return encryptSM(cipher, content, recipients, 1, true)
}

// EnvelopeMessageCFCA creates and returns an envelope data PKCS7 structure with encrypted
// recipient keys for each recipient public key.
// The OIDs use GM/T 0010 - 2012 set and the encrypted key uses ASN.1 format.
// This function uses recipient's SubjectKeyIdentifier to identify the recipient.
// This function is used for CFCA compatibility.
func EnvelopeMessageCFCA(cipher pkcs.Cipher, content []byte, recipients []*smx509.Certificate) ([]byte, error) {
	return encryptSM(cipher, content, recipients, 2, false)
}

func encryptSM(cipher pkcs.Cipher, content []byte, recipients []*smx509.Certificate, version int, isLegacyCFCA bool) ([]byte, error) {
	ed, err := NewSM2EnvelopedData(cipher, content)
	if err != nil {
		return nil, err
	}
	for _, recipient := range recipients {
		if err := ed.AddRecipient(recipient, version, func(cert *smx509.Certificate, key []byte) ([]byte, error) {
			return ed.session.EncryptdDataKey(key, cert, isLegacyCFCA)
		}); err != nil {
			return nil, err
		}
	}
	return ed.Finish()
}

// NewEnvelopedData creates a new EnvelopedData structure with the provided cipher and content.
func NewEnvelopedData(cipher pkcs.Cipher, content []byte) (*EnvelopedData, error) {
	return newEnvelopedData(cipher, content, OIDEnvelopedData, nil)
}

// NewSM2EnvelopedData creates a new EnvelopedData structure with the provided cipher and content.
// The OIDs use GM/T 0010 - 2012 set.
func NewSM2EnvelopedData(cipher pkcs.Cipher, content []byte) (*EnvelopedData, error) {
	return newEnvelopedData(cipher, content, SM2OIDEnvelopedData, nil)
}

// NewEnvelopedDataWithSession creates a new EnvelopedData structure with the provided cipher, content and sessionKey.
func NewEnvelopedDataWithSession(cipher pkcs.Cipher, content []byte, session Session) (*EnvelopedData, error) {
	return newEnvelopedData(cipher, content, OIDEnvelopedData, session)
}

// NewSM2EnvelopedDataWithSession creates a new EnvelopedData structure with the provided cipher, content and sessionKey.
// The OIDs use GM/T 0010 - 2012 set.
func NewSM2EnvelopedDataWithSession(cipher pkcs.Cipher, content []byte, session Session) (*EnvelopedData, error) {
	return newEnvelopedData(cipher, content, SM2OIDEnvelopedData, session)
}

func newEnvelopedData(cipher pkcs.Cipher, content []byte, contentType asn1.ObjectIdentifier, session Session) (*EnvelopedData, error) {
	ed := &EnvelopedData{}
	ed.session = session
	if ed.session == nil {
		ed.session = DefaultSession{}
	}

	key, err := ed.session.GenerateDataKey(cipher.KeySize())
	if err != nil {
		return nil, err
	}

	id, ciphertext, err := cipher.Encrypt(rand.Reader, key, content)
	if err != nil {
		return nil, err
	}

	ed.contentType = contentType
	ed.encryptedContentType = OIDData
	version := 0
	if SM2OIDEnvelopedData.Equal(contentType) {
		ed.encryptedContentType = SM2OIDData
		version = 1
	}
	ed.key = key
	ed.ed = envelopedData{
		Version:              version,
		EncryptedContentInfo: newEncryptedContent(ed.encryptedContentType, id, marshalEncryptedContent(ciphertext)),
	}
	return ed, nil
}

// AddRecipient adds a recipient to the EnvelopedData structure.
// version 0: IssuerAndSerialNumber
// version 1: SM2
// version 2: SubjectKeyIdentifier
func (ed *EnvelopedData) AddRecipient(cert *smx509.Certificate, version int, encryptKeyFunc func(cert *smx509.Certificate, key []byte) ([]byte, error)) error {
	if version < 0 || version > 2 {
		return errors.New("pkcs7: invalid recipient version")
	}
	encrypted, err := encryptKeyFunc(cert, ed.key)
	if err != nil {
		return err
	}
	var keyEncryptionAlgorithm asn1.ObjectIdentifier = OIDEncryptionAlgorithmRSA
	if cert.SignatureAlgorithm == smx509.SM2WithSM3 {
		keyEncryptionAlgorithm = OIDKeyEncryptionAlgorithmSM2
	}

	info := recipientInfo{
		Version: version,
		KeyEncryptionAlgorithm: pkix.AlgorithmIdentifier{
			Algorithm:  keyEncryptionAlgorithm,
			Parameters: asn1.NullRawValue,
		},
		EncryptedKey: encrypted,
	}

	if version == 2 {
		if len(cert.SubjectKeyId) == 0 {
			return errors.New("pkcs7: envelope required certificate extension SubjectKeyIdentifier")
		}
		info.SubjectKeyIdentifier = asn1.RawValue{Tag: 0, Class: asn1.ClassContextSpecific, Bytes: cert.SubjectKeyId}
	} else {
		ias, err := cert2issuerAndSerial(cert)
		if err != nil {
			return err
		}
		info.IssuerAndSerialNumber = ias
	}
	ed.ed.RecipientInfos = append(ed.ed.RecipientInfos, info)

	return nil
}

// Finish creates the final PKCS7 structure.
func (ed *EnvelopedData) Finish() ([]byte, error) {
	// Check if we need to upgrade the version to 2
	for _, recp := range ed.ed.RecipientInfos {
		if recp.Version == 2 {
			ed.ed.Version = 2
			break
		}
	}

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
	return asn1.RawValue{Tag: 0, Class: asn1.ClassContextSpecific, Bytes: content}
}
