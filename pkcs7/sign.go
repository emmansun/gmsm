package pkcs7

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"fmt"
	"hash"
	"math/big"
	"time"

	"github.com/emmansun/gmsm/sm2"
	"github.com/emmansun/gmsm/sm3"
	"github.com/emmansun/gmsm/smx509"
)

// SignedData is an opaque data structure for creating signed data payloads
type SignedData struct {
	sd             signedData
	certs          []*smx509.Certificate
	data           []byte
	isDigest       bool
	contentTypeOid asn1.ObjectIdentifier
	digestOid      asn1.ObjectIdentifier
	encryptionOid  asn1.ObjectIdentifier
}

// NewSignedData takes data and initializes a PKCS7 SignedData struct that is
// ready to be signed via AddSigner. The digest algorithm is set to SHA1 by default
// and can be changed by calling SetDigestAlgorithm.
func NewSignedData(data []byte) (*SignedData, error) {
	content, err := asn1.Marshal(data)
	if err != nil {
		return nil, err
	}
	ci := contentInfo{
		ContentType: OIDData,
		Content:     asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 0, Bytes: content, IsCompound: true},
	}
	sd := signedData{
		ContentInfo: ci,
		Version:     1,
	}
	return &SignedData{sd: sd, data: data, digestOid: OIDDigestAlgorithmSHA1, contentTypeOid: OIDSignedData}, nil
}

// NewSMSignedData takes data and initializes a PKCS7 SignedData struct that is
// ready to be signed via AddSigner. The digest algorithm is set to SM3 by default
// and can be changed by calling SetDigestAlgorithm.
func NewSMSignedData(data []byte) (*SignedData, error) {
	sd, err := NewSignedData(data)
	if err != nil {
		return nil, err
	}
	sd.sd.ContentInfo.ContentType = SM2OIDData
	sd.digestOid = OIDDigestAlgorithmSM3
	sd.contentTypeOid = SM2OIDSignedData
	return sd, nil
}

// SignerInfoConfig are optional values to include when adding a signer
type SignerInfoConfig struct {
	ExtraSignedAttributes   []Attribute
	ExtraUnsignedAttributes []Attribute
	SkipCertificates        bool // Skip adding certificates to the payload
}

type signedData struct {
	Version                    int                        `asn1:"default:1"`
	DigestAlgorithmIdentifiers []pkix.AlgorithmIdentifier `asn1:"set"`
	ContentInfo                contentInfo
	Certificates               rawCertificates        `asn1:"optional,tag:0"`
	CRLs                       []pkix.CertificateList `asn1:"optional,tag:1"`
	SignerInfos                []signerInfo           `asn1:"set"`
}

type signerInfo struct {
	Version                   int `asn1:"default:1"`
	IssuerAndSerialNumber     issuerAndSerial
	DigestAlgorithm           pkix.AlgorithmIdentifier
	AuthenticatedAttributes   []attribute `asn1:"optional,omitempty,tag:0"`
	DigestEncryptionAlgorithm pkix.AlgorithmIdentifier
	EncryptedDigest           []byte
	UnauthenticatedAttributes []attribute `asn1:"optional,omitempty,tag:1"`
}

type attribute struct {
	Type  asn1.ObjectIdentifier
	Value asn1.RawValue `asn1:"set"`
}

func marshalAttributes(attrs []attribute) ([]byte, error) {
	encodedAttributes, err := asn1.Marshal(struct {
		A []attribute `asn1:"set"`
	}{A: attrs})
	if err != nil {
		return nil, err
	}

	// Remove the leading sequence octets
	var raw asn1.RawValue
	asn1.Unmarshal(encodedAttributes, &raw)
	return raw.Bytes, nil
}

type rawCertificates struct {
	Raw asn1.RawContent
}

type issuerAndSerial struct {
	IssuerName   asn1.RawValue
	SerialNumber *big.Int
}

// SetDigestAlgorithm sets the digest algorithm to be used in the signing process.
//
// This should be called before adding signers
func (sd *SignedData) SetDigestAlgorithm(d asn1.ObjectIdentifier) {
	sd.digestOid = d
}

// SetEncryptionAlgorithm sets the encryption algorithm to be used in the signing process.
//
// This should be called before adding signers
func (sd *SignedData) SetEncryptionAlgorithm(d asn1.ObjectIdentifier) {
	sd.encryptionOid = d
}

func (sd *SignedData) SetIsDigest() {
	sd.isDigest = true
}

// AddSigner is a wrapper around AddSignerChain() that adds a signer without any parent.
func (sd *SignedData) AddSigner(ee *smx509.Certificate, pkey crypto.PrivateKey, config SignerInfoConfig) error {
	var parents []*smx509.Certificate
	return sd.AddSignerChain(ee, pkey, parents, config)
}

// AddSignerChain signs attributes about the content and adds certificates
// and signers infos to the Signed Data. The certificate and private key
// of the end-entity signer are used to issue the signature, and any
// parent of that end-entity that need to be added to the list of
// certifications can be specified in the parents slice.
//
// The signature algorithm used to hash the data is the one of the end-entity
// certificate.
func (sd *SignedData) AddSignerChain(ee *smx509.Certificate, pkey crypto.PrivateKey, parents []*smx509.Certificate, config SignerInfoConfig) error {
	if ee == nil {
		return errors.New("pkcs7: certificate is nil")
	}

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
	sd.sd.DigestAlgorithmIdentifiers = append(sd.sd.DigestAlgorithmIdentifiers,
		pkix.AlgorithmIdentifier{Algorithm: sd.digestOid, Parameters: asn1.NullRawValue},
	)
	encryptionOid, err := getOIDForEncryptionAlgorithm(pkey, sd.digestOid)
	if err != nil {
		return err
	}
	finalAttrs, signature, err := sd.signWithAttributes(pkey, config)
	if err != nil {
		return err
	}
	signer := signerInfo{
		AuthenticatedAttributes:   finalAttrs,
		DigestAlgorithm:           pkix.AlgorithmIdentifier{Algorithm: sd.digestOid, Parameters: asn1.NullRawValue},
		DigestEncryptionAlgorithm: pkix.AlgorithmIdentifier{Algorithm: encryptionOid, Parameters: asn1.NullRawValue},
		IssuerAndSerialNumber:     ias,
		EncryptedDigest:           signature,
		Version:                   1,
	}
	if err = signer.SetUnauthenticatedAttributes(config.ExtraUnsignedAttributes); err != nil {
		return err
	}

	if !config.SkipCertificates {
		sd.certs = append(sd.certs, ee)
		if len(parents) > 0 {
			sd.certs = append(sd.certs, parents...)
		}
	}
	sd.sd.SignerInfos = append(sd.sd.SignerInfos, signer)
	return nil
}

func (sd *SignedData) signWithAttributes(pkey crypto.PrivateKey, config SignerInfoConfig) ([]attribute, []byte, error) {
	hasher, err := getHashForOID(sd.digestOid)
	if err != nil {
		return nil, nil, err
	}
	h := newHash(hasher, sd.digestOid)
	h.Write(sd.data)
	messageDigest := h.Sum(nil)

	attrs := &attributes{}
	attrs.Add(OIDAttributeContentType, sd.sd.ContentInfo.ContentType)
	attrs.Add(OIDAttributeMessageDigest, messageDigest)
	attrs.Add(OIDAttributeSigningTime, time.Now().UTC())
	for _, attr := range config.ExtraSignedAttributes {
		attrs.Add(attr.Type, attr.Value)
	}
	finalAttrs, err := attrs.ForMarshalling()
	if err != nil {
		return nil, nil, err
	}
	// create signature of signed attributes
	signature, err := signAttributes(finalAttrs, pkey, hasher)
	if err != nil {
		return nil, nil, err
	}
	return finalAttrs, signature, nil
}

func newHash(hasher crypto.Hash, hashOid asn1.ObjectIdentifier) hash.Hash {
	var h hash.Hash
	if hashOid.Equal(OIDDigestAlgorithmSM3) || hashOid.Equal(OIDDigestAlgorithmSM2SM3) {
		h = sm3.New()
	} else {
		h = hasher.New()
	}
	return h
}

// SignWithoutAttr issues a signature on the content of the pkcs7 SignedData.
// Unlike AddSigner/AddSignerChain, it calculates the digest on the data alone
// and does not include any signed attributes like timestamp and so on.
//
// This function is needed to sign old Android APKs, something you probably
// shouldn't do unless you're maintaining backward compatibility for old
// applications.
func (sd *SignedData) SignWithoutAttr(ee *smx509.Certificate, pkey crypto.PrivateKey, config SignerInfoConfig) error {
	var signature []byte
	sd.sd.DigestAlgorithmIdentifiers = append(sd.sd.DigestAlgorithmIdentifiers, pkix.AlgorithmIdentifier{Algorithm: sd.digestOid, Parameters: asn1.NullRawValue})
	hasher, err := getHashForOID(sd.digestOid)
	if err != nil {
		return err
	}
	if signature, err = signData(sd.data, pkey, hasher, sd.isDigest); err != nil {
		return err
	}
	var ias issuerAndSerial
	ias.SerialNumber = ee.SerialNumber
	// no parent, the issue is the end-entity cert itself
	ias.IssuerName = asn1.RawValue{FullBytes: ee.RawIssuer}
	if sd.encryptionOid == nil {
		// if the encryption algorithm wasn't set by SetEncryptionAlgorithm,
		// infer it from the digest algorithm
		sd.encryptionOid, err = getOIDForEncryptionAlgorithm(pkey, sd.digestOid)
	}
	if err != nil {
		return err
	}
	signer := signerInfo{
		DigestAlgorithm:           pkix.AlgorithmIdentifier{Algorithm: sd.digestOid, Parameters: asn1.NullRawValue},
		DigestEncryptionAlgorithm: pkix.AlgorithmIdentifier{Algorithm: sd.encryptionOid, Parameters: asn1.NullRawValue},
		IssuerAndSerialNumber:     ias,
		EncryptedDigest:           signature,
		Version:                   1,
	}
	// create signature of signed attributes
	if !config.SkipCertificates {
		sd.certs = append(sd.certs, ee)
	}
	sd.sd.SignerInfos = append(sd.sd.SignerInfos, signer)
	return nil
}

func (si *signerInfo) SetUnauthenticatedAttributes(extraUnsignedAttrs []Attribute) error {
	unsignedAttrs := &attributes{}
	for _, attr := range extraUnsignedAttrs {
		unsignedAttrs.Add(attr.Type, attr.Value)
	}
	finalUnsignedAttrs, err := unsignedAttrs.ForMarshalling()
	if err != nil {
		return err
	}

	si.UnauthenticatedAttributes = finalUnsignedAttrs

	return nil
}

// AddCertificate adds the certificate to the payload. Useful for parent certificates
func (sd *SignedData) AddCertificate(cert *smx509.Certificate) {
	sd.certs = append(sd.certs, cert)
}

// Detach removes content from the signed data struct to make it a detached signature.
// This must be called right before Finish()
func (sd *SignedData) Detach() {
	sd.sd.ContentInfo.Content = asn1.RawValue{}
}

// GetSignedData returns the private Signed Data
func (sd *SignedData) GetSignedData() *signedData {
	return &sd.sd
}

// Finish marshals the content and its signers
func (sd *SignedData) Finish() ([]byte, error) {
	if len(sd.certs) > 0 {
		sd.sd.Certificates = marshalCertificates(sd.certs)
	}
	inner, err := asn1.Marshal(sd.sd)
	if err != nil {
		return nil, err
	}
	outer := contentInfo{
		ContentType: sd.contentTypeOid,
		Content:     asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 0, Bytes: inner, IsCompound: true},
	}
	return asn1.Marshal(outer)
}

// RemoveAuthenticatedAttributes removes authenticated attributes from signedData
// similar to OpenSSL's PKCS7_NOATTR or -noattr flags
func (sd *SignedData) RemoveAuthenticatedAttributes() {
	for i := range sd.sd.SignerInfos {
		sd.sd.SignerInfos[i].AuthenticatedAttributes = nil
	}
}

// RemoveUnauthenticatedAttributes removes unauthenticated attributes from signedData
func (sd *SignedData) RemoveUnauthenticatedAttributes() {
	for i := range sd.sd.SignerInfos {
		sd.sd.SignerInfos[i].UnauthenticatedAttributes = nil
	}
}

// verifyPartialChain checks that a given cert is issued by the first parent in the list,
// then continue down the path. It doesn't require the last parent to be a root CA,
// or to be trusted in any truststore. It simply verifies that the chain provided, albeit
// partial, makes sense.
func verifyPartialChain(cert *smx509.Certificate, parents []*smx509.Certificate) error {
	if len(parents) == 0 {
		return fmt.Errorf("pkcs7: zero parents provided to verify the signature of certificate %q", cert.Subject.CommonName)
	}
	err := cert.CheckSignatureFrom(parents[0])
	if err != nil {
		return fmt.Errorf("pkcs7: certificate signature from parent is invalid: %v", err)
	}
	if len(parents) == 1 {
		// there is no more parent to check, return
		return nil
	}
	return verifyPartialChain(parents[0], parents[1:])
}

func cert2issuerAndSerial(cert *smx509.Certificate) (issuerAndSerial, error) {
	var ias issuerAndSerial
	// The issuer RDNSequence has to match exactly the sequence in the certificate
	// We cannot use cert.Issuer.ToRDNSequence() here since it mangles the sequence
	ias.IssuerName = asn1.RawValue{FullBytes: cert.RawIssuer}
	ias.SerialNumber = cert.SerialNumber

	return ias, nil
}

// signs the DER encoded form of the attributes with the private key
func signAttributes(attrs []attribute, pkey crypto.PrivateKey, hasher crypto.Hash) ([]byte, error) {
	attrBytes, err := marshalAttributes(attrs)
	if err != nil {
		return nil, err
	}
	return signData(attrBytes, pkey, hasher, false)
}

// signData signs the provided data using the given private key and hash function.
// It returns the signed data or an error if the signing process fails.
func signData(data []byte, pkey crypto.PrivateKey, hasher crypto.Hash, isDigest bool) ([]byte, error) {
	key, ok := pkey.(crypto.Signer)
	if !ok {
		return nil, errors.New("pkcs7: private key does not implement crypto.Signer")
	}
	hash := data
	var opts crypto.SignerOpts = hasher
	if isDigest {
		opts = crypto.Hash(0)
	}

	if !hasher.Available() {
		if sm2.IsSM2PublicKey(key.Public()) {
			if isDigest {
				opts = sm2.NewSM2SignerOption(false, nil)
			} else {
				opts = sm2.DefaultSM2SignerOpts
			}
			switch realKey := key.(type) {
			case *ecdsa.PrivateKey:
				{
					sm2Key := new(sm2.PrivateKey)
					sm2Key.PrivateKey = *realKey
					key = sm2Key
				}
			}
		} else {
			return nil, fmt.Errorf("pkcs7: unsupported hash function %s", hasher)
		}
	} else {
		if !isDigest {
			h := hasher.New()
			h.Write(data)
			hash = h.Sum(nil)
		}
	}
	return key.Sign(rand.Reader, hash, opts)
}

// concats and wraps the certificates in the RawValue structure
func marshalCertificates(certs []*smx509.Certificate) rawCertificates {
	var buf bytes.Buffer
	for _, cert := range certs {
		buf.Write(cert.Raw)
	}
	rawCerts, _ := marshalCertificateBytes(buf.Bytes())
	return rawCerts
}

// Even though, the tag & length are stripped out during marshalling the
// RawContent, we have to encode it into the RawContent. If its missing,
// then `asn1.Marshal()` will strip out the certificate wrapper instead.
func marshalCertificateBytes(certs []byte) (rawCertificates, error) {
	var val = asn1.RawValue{Bytes: certs, Class: asn1.ClassContextSpecific, Tag: 0, IsCompound: true}
	b, err := asn1.Marshal(val)
	if err != nil {
		return rawCertificates{}, err
	}
	return rawCertificates{Raw: b}, nil
}

// DegenerateCertificate creates a signed data structure containing only the
// provided certificate or certificate chain.
func DegenerateCertificate(cert []byte) ([]byte, error) {
	rawCert, err := marshalCertificateBytes(cert)
	if err != nil {
		return nil, err
	}
	emptyContent := contentInfo{ContentType: OIDData}
	sd := signedData{
		Version:      1,
		ContentInfo:  emptyContent,
		Certificates: rawCert,
		CRLs:         []pkix.CertificateList{},
	}
	content, err := asn1.Marshal(sd)
	if err != nil {
		return nil, err
	}
	signedContent := contentInfo{
		ContentType: OIDSignedData,
		Content:     asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 0, Bytes: content, IsCompound: true},
	}
	return asn1.Marshal(signedContent)
}
