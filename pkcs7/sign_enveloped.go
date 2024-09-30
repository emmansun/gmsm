package pkcs7

import (
	"crypto"
	"crypto/rand"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"

	"github.com/emmansun/gmsm/pkcs"
	"github.com/emmansun/gmsm/sm2"
	"github.com/emmansun/gmsm/smx509"
)

// It is recommended to use a sequential combination of the signed-data and the enveloped-data content types instead of using the signed-and-enveloped-data content type,
// since the signed-and-enveloped-data content type does not have authenticated or unauthenticated attributes,
// and does not provide enveloping of signer information other than the signature.
type signedEnvelopedData struct {
	Version                    int                        `asn1:"default:1"`
	RecipientInfos             []recipientInfo            `asn1:"set"`
	DigestAlgorithmIdentifiers []pkix.AlgorithmIdentifier `asn1:"set"`
	EncryptedContentInfo       encryptedContentInfo
	Certificates               rawCertificates        `asn1:"optional,tag:0"`
	CRLs                       []pkix.CertificateList `asn1:"optional,tag:1"`
	SignerInfos                []signerInfo           `asn1:"set"`
}

func (data signedEnvelopedData) GetRecipient(cert *smx509.Certificate) *recipientInfo {
	for _, recp := range data.RecipientInfos {
		if isCertMatchForIssuerAndSerial(cert, recp.IssuerAndSerialNumber) {
			return &recp
		}
	}
	return nil
}

// GetRecipients returns the list of recipients (READONLY) for the enveloped data
func (data signedEnvelopedData) GetRecipients() ([]IssuerAndSerial, error) {
	var recipients []IssuerAndSerial
	for _, recp := range data.RecipientInfos {
		recipients = append(recipients, newIssuerAndSerial(recp.IssuerAndSerialNumber))
	}
	return recipients, nil
}

func (data signedEnvelopedData) GetEncryptedContentInfo() *encryptedContentInfo {
	return &data.EncryptedContentInfo
}

func parseSignedEnvelopedData(data []byte) (*PKCS7, error) {
	var sed signedEnvelopedData
	if _, err := asn1.Unmarshal(data, &sed); err != nil {
		return nil, err
	}
	certs, err := sed.Certificates.Parse()
	if err != nil {
		return nil, err
	}

	return &PKCS7{
		Certificates: certs,
		CRLs:         sed.CRLs,
		Signers:      sed.SignerInfos,
		raw:          sed}, nil
}

type VerifyFunc func() error

// DecryptAndVerifyOnlyOne decrypts encrypted content info for the only recipient private key
// and verifies the signature.
func (p7 *PKCS7) DecryptAndVerifyOnlyOne(pkey crypto.PrivateKey, verifyFunc VerifyFunc) ([]byte, error) {
	sed, ok := p7.raw.(signedEnvelopedData)
	if !ok {
		return nil, errors.New("pkcs7: it's NOT SignedAndEvelopedData")
	}
	if len(sed.RecipientInfos) != 1 {
		return nil, errors.New("pkcs7: more than one recipients or no receipient")
	}
	defer func() {
		p7.Content = nil
	}()
	plaintext, err := p7.decryptSED(&sed, &sed.RecipientInfos[0], pkey)
	if err != nil {
		return nil, err
	}
	if verifyFunc != nil {
		p7.Content = plaintext
		if err = verifyFunc(); err != nil {
			return nil, err
		}
	}
	return plaintext, nil
}

// DecryptAndVerify decrypts encrypted content info for recipient cert and private key
// and verifies the signature.
func (p7 *PKCS7) DecryptAndVerify(cert *smx509.Certificate, pkey crypto.PrivateKey, verifyFunc VerifyFunc) ([]byte, error) {
	sed, ok := p7.raw.(signedEnvelopedData)
	if !ok {
		return nil, errors.New("pkcs7: it's NOT SignedAndEvelopedData")
	}
	recipient := sed.GetRecipient(cert)
	if recipient == nil {
		return nil, errors.New("pkcs7: no enveloped recipient for provided certificate")
	}
	defer func() {
		p7.Content = nil
	}()
	plaintext, err := p7.decryptSED(&sed, recipient, pkey)
	if err != nil {
		return nil, err
	}
	if verifyFunc != nil {
		p7.Content = plaintext
		if err = verifyFunc(); err != nil {
			return nil, err
		}
	}
	return plaintext, nil
}

func (p7 *PKCS7) decryptSED(sed *signedEnvelopedData, recipient *recipientInfo, pkey crypto.PrivateKey) ([]byte, error) {
	switch pkey := pkey.(type) {
	case crypto.Decrypter:
		// Generic case to handle anything that provides the crypto.Decrypter interface.
		contentKey, err := pkey.Decrypt(rand.Reader, recipient.EncryptedKey, nil)
		if err != nil {
			return nil, err
		}
		return sed.GetEncryptedContentInfo().decrypt(contentKey)
	default:
		return nil, ErrUnsupportedAlgorithm
	}
}

// SignedAndEnvelopedData is an opaque data structure for creating signed and enveloped data payloads
type SignedAndEnvelopedData struct {
	sed            signedEnvelopedData
	certs          []*smx509.Certificate
	data, cek      []byte
	contentTypeOid asn1.ObjectIdentifier
	digestOid      asn1.ObjectIdentifier
}

// NewSignedAndEnvelopedData takes data and cipher and initializes a new PKCS7 SignedAndEnvelopedData structure
// that is ready to be signed via AddSigner and encrypted via AddRecipient. The digest algorithm is set to SHA1 by default
// and can be changed by calling SetDigestAlgorithm.
func NewSignedAndEnvelopedData(data []byte, cipher pkcs.Cipher) (*SignedAndEnvelopedData, error) {
	var key []byte
	var err error

	// Create key
	key = make([]byte, cipher.KeySize())
	_, err = rand.Read(key)
	if err != nil {
		return nil, err
	}

	id, ciphertext, err := cipher.Encrypt(rand.Reader, key, data)
	if err != nil {
		return nil, err
	}

	sed := signedEnvelopedData{
		Version: 1, // 0 or 1?
		EncryptedContentInfo: encryptedContentInfo{
			ContentType:                OIDData,
			ContentEncryptionAlgorithm: *id,
			EncryptedContent:           marshalEncryptedContent(ciphertext),
		},
	}
	return &SignedAndEnvelopedData{sed: sed, data: data, cek: key, digestOid: OIDDigestAlgorithmSHA1, contentTypeOid: OIDSignedEnvelopedData}, nil
}

// NewSMSignedAndEnvelopedData takes data and cipher and initializes a new PKCS7(SM) SignedAndEnvelopedData structure
// that is ready to be signed via AddSigner and encrypted via AddRecipient. The digest algorithm is set to SM3 by default.
func NewSMSignedAndEnvelopedData(data []byte, cipher pkcs.Cipher) (*SignedAndEnvelopedData, error) {
	sd, err := NewSignedAndEnvelopedData(data, cipher)
	if err != nil {
		return nil, err
	}
	sd.contentTypeOid = SM2OIDSignedEnvelopedData
	sd.digestOid = OIDDigestAlgorithmSM3
	sd.sed.EncryptedContentInfo.ContentType = SM2OIDData
	return sd, nil
}

// SetDigestAlgorithm sets the digest algorithm to be used in the signing process.
//
// This should be called before adding signers
func (saed *SignedAndEnvelopedData) SetDigestAlgorithm(d asn1.ObjectIdentifier) {
	saed.digestOid = d
}

// AddSigner is a wrapper around AddSignerChain() that adds a signer without any parent.
func (saed *SignedAndEnvelopedData) AddSigner(ee *smx509.Certificate, pkey crypto.PrivateKey) error {
	var parents []*smx509.Certificate
	return saed.AddSignerChain(ee, pkey, parents)
}

func (saed *SignedAndEnvelopedData) AddSignerChain(ee *smx509.Certificate, pkey crypto.PrivateKey, parents []*smx509.Certificate) error {
	// Following RFC 2315, 9.2 SignerInfo type, the distinguished name of
	// the issuer of the end-entity signer is stored in the issuerAndSerialNumber
	// section of the SignedData.SignerInfo, alongside the serial number of
	// the end-entity.
	var ias issuerAndSerial
	ias.SerialNumber = ee.SerialNumber
	if len(parents) == 0 {
		// no parent, the issuer is the end-entity cert itself
		ias.IssuerName = asn1.RawValue{FullBytes: ee.RawIssuer}
	} else {
		err := verifyPartialChain(ee, parents)
		if err != nil {
			return err
		}
		// the first parent is the issuer
		ias.IssuerName = asn1.RawValue{FullBytes: parents[0].RawSubject}
	}
	saed.sed.DigestAlgorithmIdentifiers = append(saed.sed.DigestAlgorithmIdentifiers,
		pkix.AlgorithmIdentifier{Algorithm: saed.digestOid},
	)
	hasher, err := getHashForOID(saed.digestOid)
	if err != nil {
		return err
	}

	signatureOid, err := getOIDForEncryptionAlgorithm(pkey, saed.digestOid)
	if err != nil {
		return err
	}
	key, ok := pkey.(crypto.Signer)
	if !ok {
		return errors.New("pkcs7: private key does not implement crypto.Signer")
	}

	var signOpt crypto.SignerOpts
	var tobeSigned []byte

	if _, isSM2 := pkey.(sm2.Signer); isSM2 {
		signOpt = sm2.DefaultSM2SignerOpts
		tobeSigned = saed.data
	} else {
		signOpt = hasher
		h := newHash(hasher, saed.digestOid)
		h.Write(saed.data)
		tobeSigned = h.Sum(nil)
	}
	signature, err := key.Sign(rand.Reader, tobeSigned, signOpt)
	if err != nil {
		return err
	}
	signer := signerInfo{
		DigestAlgorithm:           pkix.AlgorithmIdentifier{Algorithm: saed.digestOid},
		DigestEncryptionAlgorithm: pkix.AlgorithmIdentifier{Algorithm: signatureOid},
		IssuerAndSerialNumber:     ias,
		EncryptedDigest:           signature,
		Version:                   1,
	}
	saed.certs = append(saed.certs, ee)
	if len(parents) > 0 {
		saed.certs = append(saed.certs, parents...)
	}
	saed.sed.SignerInfos = append(saed.sed.SignerInfos, signer)
	return nil
}

// AddCertificate adds the certificate to the payload. Useful for parent certificates
func (saed *SignedAndEnvelopedData) AddCertificate(cert *smx509.Certificate) {
	saed.certs = append(saed.certs, cert)
}

// AddRecipient adds a recipient to the payload
func (saed *SignedAndEnvelopedData) AddRecipient(recipient *smx509.Certificate) error {
	encryptedKey, err := encryptKey(saed.cek, recipient, false) //TODO: check if CFCA has such function
	if err != nil {
		return err
	}
	ias, err := cert2issuerAndSerial(recipient)
	if err != nil {
		return err
	}
	var keyEncryptionAlgorithm asn1.ObjectIdentifier = OIDEncryptionAlgorithmRSA
	if recipient.SignatureAlgorithm == smx509.SM2WithSM3 {
		keyEncryptionAlgorithm = OIDKeyEncryptionAlgorithmSM2
	}
	info := recipientInfo{
		Version:               1,
		IssuerAndSerialNumber: ias,
		KeyEncryptionAlgorithm: pkix.AlgorithmIdentifier{
			Algorithm: keyEncryptionAlgorithm,
		},
		EncryptedKey: encryptedKey,
	}
	saed.sed.RecipientInfos = append(saed.sed.RecipientInfos, info)
	return nil
}

// Finish marshals the content and its signers
func (saed *SignedAndEnvelopedData) Finish() ([]byte, error) {
	saed.sed.Certificates = marshalCertificates(saed.certs)
	inner, err := asn1.Marshal(saed.sed)
	if err != nil {
		return nil, err
	}
	outer := contentInfo{
		ContentType: saed.contentTypeOid,
		Content:     asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 0, Bytes: inner, IsCompound: true},
	}
	return asn1.Marshal(outer)
}
