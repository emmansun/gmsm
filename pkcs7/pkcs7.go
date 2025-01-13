// Package pkcs7 implements parsing and generation of some PKCS#7 structures.
package pkcs7

import (
	"bytes"
	"crypto"
	"crypto/dsa"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"fmt"
	"sort"

	_ "crypto/sha1" // for crypto.SHA1

	"github.com/emmansun/gmsm/sm2"
	"github.com/emmansun/gmsm/smx509"
)

// PKCS7 Represents a PKCS7 structure
type PKCS7 struct {
	Content      []byte
	Certificates []*smx509.Certificate
	CRLs         []pkix.CertificateList
	Signers      []signerInfo
	isDigest     bool
	raw          any
	session      Session
}

type contentInfo struct {
	ContentType asn1.ObjectIdentifier
	Content     asn1.RawValue `asn1:"explicit,optional,tag:0"`
}

// ErrUnsupportedContentType is returned when a PKCS7 content is not supported.
// Currently only Data (1.2.840.113549.1.7.1), Signed Data (1.2.840.113549.1.7.2),
// and Enveloped Data are supported (1.2.840.113549.1.7.3)
var ErrUnsupportedContentType = errors.New("pkcs7: cannot parse data: unimplemented content type")

type unsignedData []byte

var (
	// Signed Data OIDs
	OIDData                   = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 1}
	OIDSignedData             = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 2}
	OIDEnvelopedData          = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 3}
	OIDSignedEnvelopedData    = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 4}
	OIDDigestData             = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 5}
	OIDEncryptedData          = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 6}
	OIDAttributeContentType   = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 3}
	OIDAttributeMessageDigest = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 4}
	OIDAttributeSigningTime   = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 5}

	// Digest Algorithms
	OIDDigestAlgorithmSHA1   = asn1.ObjectIdentifier{1, 3, 14, 3, 2, 26}
	OIDDigestAlgorithmSHA256 = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 1}
	OIDDigestAlgorithmSHA384 = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 2}
	OIDDigestAlgorithmSHA512 = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 3}

	OIDDigestAlgorithmDSA     = asn1.ObjectIdentifier{1, 2, 840, 10040, 4, 1}
	OIDDigestAlgorithmDSASHA1 = asn1.ObjectIdentifier{1, 2, 840, 10040, 4, 3}

	OIDDigestAlgorithmECDSASHA1   = asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 1}
	OIDDigestAlgorithmECDSASHA256 = asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 2}
	OIDDigestAlgorithmECDSASHA384 = asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 3}
	OIDDigestAlgorithmECDSASHA512 = asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 4}

	// Signature Algorithms
	OIDEncryptionAlgorithmRSA       = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 1}
	OIDEncryptionAlgorithmRSASHA1   = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 5}
	OIDEncryptionAlgorithmRSASHA256 = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 11}
	OIDEncryptionAlgorithmRSASHA384 = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 12}
	OIDEncryptionAlgorithmRSASHA512 = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 13}

	OIDEncryptionAlgorithmECDSAP256 = asn1.ObjectIdentifier{1, 2, 840, 10045, 3, 1, 7}
	OIDEncryptionAlgorithmECDSAP384 = asn1.ObjectIdentifier{1, 3, 132, 0, 34}
	OIDEncryptionAlgorithmECDSAP521 = asn1.ObjectIdentifier{1, 3, 132, 0, 35}
)

var (
	// SM2 Signed Data OIDs
	// 《GB/T 35275-2017 信息安全技术 SM2密码算法加密签名消息语法规范》
	SM2OIDData                = asn1.ObjectIdentifier{1, 2, 156, 10197, 6, 1, 4, 2, 1}
	SM2OIDSignedData          = asn1.ObjectIdentifier{1, 2, 156, 10197, 6, 1, 4, 2, 2}
	SM2OIDEnvelopedData       = asn1.ObjectIdentifier{1, 2, 156, 10197, 6, 1, 4, 2, 3}
	SM2OIDSignedEnvelopedData = asn1.ObjectIdentifier{1, 2, 156, 10197, 6, 1, 4, 2, 4}
	SM2OIDEncryptedData       = asn1.ObjectIdentifier{1, 2, 156, 10197, 6, 1, 4, 2, 5}

	// Digest Algorithms
	OIDDigestAlgorithmSM3 = asn1.ObjectIdentifier{1, 2, 156, 10197, 1, 401}
	// SM2Sign-with-SM3
	OIDDigestAlgorithmSM2SM3 = asn1.ObjectIdentifier{1, 2, 156, 10197, 1, 501}
	// Signature Algorithms SM2-1
	OIDDigestEncryptionAlgorithmSM2 = asn1.ObjectIdentifier{1, 2, 156, 10197, 1, 301, 1}

	// Encryption Algorithms SM2-3
	OIDKeyEncryptionAlgorithmSM2 = asn1.ObjectIdentifier{1, 2, 156, 10197, 1, 301, 3}

	//SM9 Signed Data OIDs
	SM9OIDData                = asn1.ObjectIdentifier{1, 2, 156, 10197, 6, 1, 4, 4, 1}
	SM9OIDSignedData          = asn1.ObjectIdentifier{1, 2, 156, 10197, 6, 1, 4, 4, 2}
	SM9OIDEnvelopedData       = asn1.ObjectIdentifier{1, 2, 156, 10197, 6, 1, 4, 4, 3}
	SM9OIDSignedEnvelopedData = asn1.ObjectIdentifier{1, 2, 156, 10197, 6, 1, 4, 4, 4}
	SM9OIDEncryptedData       = asn1.ObjectIdentifier{1, 2, 156, 10197, 6, 1, 4, 4, 5}

	// SM9Sign-with-SM3
	OIDDigestAlgorithmSM9SM3 = asn1.ObjectIdentifier{1, 2, 156, 10197, 1, 502}

	// Signature Algorithms SM9-1
	OIDDigestEncryptionAlgorithmSM9 = asn1.ObjectIdentifier{1, 2, 156, 10197, 1, 302, 1}

	// Encryption Algorithms SM9-3
	OIDKeyEncryptionAlgorithmSM9 = asn1.ObjectIdentifier{1, 2, 156, 10197, 1, 302, 3}
)

func getHashForOID(oid asn1.ObjectIdentifier) (crypto.Hash, error) {
	switch {
	case oid.Equal(OIDDigestAlgorithmSHA1), oid.Equal(OIDDigestAlgorithmECDSASHA1),
		oid.Equal(OIDDigestAlgorithmDSA), oid.Equal(OIDDigestAlgorithmDSASHA1),
		oid.Equal(OIDEncryptionAlgorithmRSA):
		return crypto.SHA1, nil
	case oid.Equal(OIDDigestAlgorithmSHA256), oid.Equal(OIDDigestAlgorithmECDSASHA256):
		return crypto.SHA256, nil
	case oid.Equal(OIDDigestAlgorithmSHA384), oid.Equal(OIDDigestAlgorithmECDSASHA384):
		return crypto.SHA384, nil
	case oid.Equal(OIDDigestAlgorithmSHA512), oid.Equal(OIDDigestAlgorithmECDSASHA512):
		return crypto.SHA512, nil
	case oid.Equal(OIDDigestAlgorithmSM3), oid.Equal(OIDDigestAlgorithmSM2SM3):
		return crypto.Hash(0), nil
	}
	return crypto.Hash(0), fmt.Errorf("pkcs7: cannot get hash from oid %v", oid)
}

// getDigestOIDForSignatureAlgorithm takes an x509.SignatureAlgorithm
// and returns the corresponding OID digest algorithm
func getDigestOIDForSignatureAlgorithm(digestAlg x509.SignatureAlgorithm) (asn1.ObjectIdentifier, error) {
	switch digestAlg {
	case x509.SHA1WithRSA, x509.ECDSAWithSHA1:
		return OIDDigestAlgorithmSHA1, nil
	case x509.SHA256WithRSA, x509.ECDSAWithSHA256:
		return OIDDigestAlgorithmSHA256, nil
	case x509.SHA384WithRSA, x509.ECDSAWithSHA384:
		return OIDDigestAlgorithmSHA384, nil
	case x509.SHA512WithRSA, x509.ECDSAWithSHA512:
		return OIDDigestAlgorithmSHA512, nil
	case smx509.SM2WithSM3:
		return OIDDigestAlgorithmSM3, nil
	}
	return nil, fmt.Errorf("pkcs7: cannot convert hash to oid, unknown hash algorithm")
}

// getOIDForEncryptionAlgorithm takes the public or private key type of the signer and
// the OID of a digest algorithm to return the appropriate signerInfo.DigestEncryptionAlgorithm
func getOIDForEncryptionAlgorithm(pkey any, OIDDigestAlg asn1.ObjectIdentifier) (asn1.ObjectIdentifier, error) {
	switch k := pkey.(type) {
	case *rsa.PrivateKey, *rsa.PublicKey:
		switch {
		default:
			return OIDEncryptionAlgorithmRSA, nil
		case OIDDigestAlg.Equal(OIDEncryptionAlgorithmRSA):
			return OIDEncryptionAlgorithmRSA, nil
		case OIDDigestAlg.Equal(OIDDigestAlgorithmSHA1):
			return OIDEncryptionAlgorithmRSASHA1, nil
		case OIDDigestAlg.Equal(OIDDigestAlgorithmSHA256):
			return OIDEncryptionAlgorithmRSASHA256, nil
		case OIDDigestAlg.Equal(OIDDigestAlgorithmSHA384):
			return OIDEncryptionAlgorithmRSASHA384, nil
		case OIDDigestAlg.Equal(OIDDigestAlgorithmSHA512):
			return OIDEncryptionAlgorithmRSASHA512, nil
		}
	case *ecdsa.PrivateKey, *ecdsa.PublicKey:
		switch {
		case OIDDigestAlg.Equal(OIDDigestAlgorithmSHA1):
			return OIDDigestAlgorithmECDSASHA1, nil
		case OIDDigestAlg.Equal(OIDDigestAlgorithmSHA256):
			return OIDDigestAlgorithmECDSASHA256, nil
		case OIDDigestAlg.Equal(OIDDigestAlgorithmSHA384):
			return OIDDigestAlgorithmECDSASHA384, nil
		case OIDDigestAlg.Equal(OIDDigestAlgorithmSHA512):
			return OIDDigestAlgorithmECDSASHA512, nil
		case OIDDigestAlg.Equal(OIDDigestAlgorithmSM3):
			// Do we need further checking?
			return OIDDigestEncryptionAlgorithmSM2, nil
		}
	case *sm2.PrivateKey:
		return OIDDigestEncryptionAlgorithmSM2, nil
	case *dsa.PrivateKey, *dsa.PublicKey:
		return OIDDigestAlgorithmDSA, nil
	case crypto.Signer:
		return getOIDForEncryptionAlgorithm(k.Public(), OIDDigestAlg)
	}
	return nil, fmt.Errorf("pkcs7: cannot convert encryption algorithm to oid, unknown or unsupported private key type %T", pkey)

}

// Parse decodes a DER encoded PKCS7 package and assign the default session to the PKCS7 object
func Parse(data []byte) (p7 *PKCS7, err error) {
	return ParseWithSession(DefaultSession{}, data)
}

// ParseWithSession decodes a DER encoded PKCS7 package and assign the session to the PKCS7 object
func ParseWithSession(session Session, data []byte) (p7 *PKCS7, err error) {
	if len(data) == 0 {
		return nil, errors.New("pkcs7: input data is empty")
	}
	var info contentInfo
	der, err := ber2der(data)
	if err != nil {
		return nil, err
	}
	rest, err := asn1.Unmarshal(der, &info)
	if len(rest) > 0 {
		err = asn1.SyntaxError{Msg: "trailing data"}
		return
	}
	if err != nil {
		return
	}

	switch {
	case info.ContentType.Equal(OIDSignedData) || info.ContentType.Equal(SM2OIDSignedData):
		return parseSignedData(info.Content.Bytes)
	case info.ContentType.Equal(OIDEnvelopedData) || info.ContentType.Equal(SM2OIDEnvelopedData):
		return parseEnvelopedData(session, info.Content.Bytes)
	case info.ContentType.Equal(OIDEncryptedData) || info.ContentType.Equal(SM2OIDEncryptedData):
		return parseEncryptedData(session, info.Content.Bytes)
	case info.ContentType.Equal(OIDSignedEnvelopedData) || info.ContentType.Equal(SM2OIDSignedEnvelopedData):
		return parseSignedEnvelopedData(session, info.Content.Bytes)
	default:
		return nil, ErrUnsupportedContentType
	}
}

func parseEnvelopedData(session Session, data []byte) (*PKCS7, error) {
	var ed envelopedData
	if _, err := asn1.Unmarshal(data, &ed); err != nil {
		return nil, err
	}
	return &PKCS7{
		raw:     ed,
		session: session,
	}, nil
}

func parseEncryptedData(session Session, data []byte) (*PKCS7, error) {
	var ed encryptedData
	if _, err := asn1.Unmarshal(data, &ed); err != nil {
		return nil, err
	}
	return &PKCS7{
		raw:     ed,
		session: session,
	}, nil
}

func (raw rawCertificates) Parse() ([]*smx509.Certificate, error) {
	if len(raw.Raw) == 0 {
		return nil, nil
	}

	var val asn1.RawValue
	if _, err := asn1.Unmarshal(raw.Raw, &val); err != nil {
		return nil, err
	}

	return smx509.ParseCertificates(val.Bytes)
}

func isCertMatchForIssuerAndSerial(cert *smx509.Certificate, ias issuerAndSerial) bool {
	return ias.SerialNumber != nil && cert.SerialNumber.Cmp(ias.SerialNumber) == 0 && bytes.Equal(cert.RawIssuer, ias.IssuerName.FullBytes)
}

// Attribute represents a key value pair attribute. Value must be marshalable byte
// `encoding/asn1`
type Attribute struct {
	Type  asn1.ObjectIdentifier
	Value any
}

type attributes struct {
	types  []asn1.ObjectIdentifier
	values []any
}

// Add adds the attribute, maintaining insertion order
func (attrs *attributes) Add(attrType asn1.ObjectIdentifier, value any) {
	attrs.types = append(attrs.types, attrType)
	attrs.values = append(attrs.values, value)
}

type sortableAttribute struct {
	SortKey   []byte
	Attribute attribute
}

type attributeSet []sortableAttribute

func (sa attributeSet) Len() int {
	return len(sa)
}

func (sa attributeSet) Less(i, j int) bool {
	return bytes.Compare(sa[i].SortKey, sa[j].SortKey) < 0
}

func (sa attributeSet) Swap(i, j int) {
	sa[i], sa[j] = sa[j], sa[i]
}

func (sa attributeSet) Attributes() []attribute {
	attrs := make([]attribute, len(sa))
	for i, attr := range sa {
		attrs[i] = attr.Attribute
	}
	return attrs
}

func (attrs *attributes) ForMarshalling() ([]attribute, error) {
	sortables := make(attributeSet, len(attrs.types))
	for i := range sortables {
		attrType := attrs.types[i]
		attrValue := attrs.values[i]
		asn1Value, err := asn1.Marshal(attrValue)
		if err != nil {
			return nil, err
		}
		attr := attribute{
			Type:  attrType,
			Value: asn1.RawValue{Tag: 17, IsCompound: true, Bytes: asn1Value}, // 17 == SET tag
		}
		encoded, err := asn1.Marshal(attr)
		if err != nil {
			return nil, err
		}
		sortables[i] = sortableAttribute{
			SortKey:   encoded,
			Attribute: attr,
		}
	}
	sort.Sort(sortables)
	return sortables.Attributes(), nil
}
