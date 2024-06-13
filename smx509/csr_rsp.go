// Marshal & Parse CSRResponse which is defined in GM/T 0092-2020
// Specification of certificate request syntax based on SM2 cryptographic algorithm.

package smx509

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/rand"
	"encoding/asn1"
	"errors"

	"github.com/emmansun/gmsm/sm2"
)

// CSRResponse represents the response of a certificate signing request.
type CSRResponse struct {
	SignCerts         []*Certificate
	EncryptPrivateKey *sm2.PrivateKey
	EncryptCerts      []*Certificate
}

type tbsCSRResponse struct {
	SignCerts           rawCertificates
	EncryptedPrivateKey asn1.RawValue   `asn1:"optional,tag:0"`
	EncryptCerts        rawCertificates `asn1:"optional,tag:1"`
}

type rawCertificates struct {
	Raw asn1.RawContent
}

// ParseCSRResponse parses a CSRResponse from DER format.
// We do NOT verify the cert chain here, it's the caller's responsibility.
func ParseCSRResponse(signPrivateKey *sm2.PrivateKey, der []byte) (CSRResponse, error) {
	result := CSRResponse{}
	resp := &tbsCSRResponse{}
	rest, err := asn1.Unmarshal(der, resp)
	if err != nil || len(rest) > 0 {
		return result, errors.New("smx509: invalid CSRResponse asn1 data")
	}
	signCerts, err := resp.SignCerts.Parse()
	if err != nil || len(signCerts) == 0 {
		return result, errors.New("smx509: invalid sign certificates")
	}

	// check sign public key against the private key
	if !signPrivateKey.PublicKey.Equal(signCerts[0].PublicKey) {
		return result, errors.New("smx509: sign cert public key mismatch")
	}

	var encPrivateKey *sm2.PrivateKey
	if len(resp.EncryptedPrivateKey.Bytes) > 0 {
		encPrivateKey, err = sm2.ParseEnvelopedPrivateKey(signPrivateKey, resp.EncryptedPrivateKey.Bytes)
		if err != nil {
			return result, err
		}
	}
	var encryptCerts []*Certificate
	if len(resp.EncryptCerts.Raw) > 0 {
		encryptCerts, err = resp.EncryptCerts.Parse()
		if err != nil {
			return result, err
		}
	}

	// check the public key of the encrypt certificate
	if encPrivateKey != nil && len(encryptCerts) == 0 {
		return result, errors.New("smx509: missing encrypt certificate")
	}

	if encPrivateKey != nil && !encPrivateKey.PublicKey.Equal(encryptCerts[0].PublicKey) {
		return result, errors.New("smx509: encrypt key pair mismatch")
	}

	result.SignCerts = signCerts
	result.EncryptPrivateKey = encPrivateKey
	result.EncryptCerts = encryptCerts
	return result, nil
}

// MarshalCSRResponse marshals a CSRResponse to DER format.
func MarshalCSRResponse(signCerts []*Certificate, encryptPrivateKey *sm2.PrivateKey, encryptCerts []*Certificate) ([]byte, error) {
	if len(signCerts) == 0 {
		return nil, errors.New("smx509: no sign certificate")
	}
	signPubKey, ok := signCerts[0].PublicKey.(*ecdsa.PublicKey)
	if !ok || !sm2.IsSM2PublicKey(signPubKey) {
		return nil, errors.New("smx509: invalid sign public key")
	}

	// check the public key of the encrypt certificate
	if encryptPrivateKey != nil && len(encryptCerts) == 0 {
		return nil, errors.New("smx509: missing encrypt certificate")
	}
	if encryptPrivateKey != nil && !encryptPrivateKey.PublicKey.Equal(encryptCerts[0].PublicKey) {
		return nil, errors.New("smx509: encrypt key pair mismatch")
	}

	resp := tbsCSRResponse{}
	resp.SignCerts = marshalCertificates(signCerts)
	if encryptPrivateKey != nil && len(encryptCerts) > 0 {
		privateKeyBytes, err := sm2.MarshalEnvelopedPrivateKey(rand.Reader, signPubKey, encryptPrivateKey)
		if err != nil {
			return nil, err
		}
		resp.EncryptedPrivateKey = asn1.RawValue{Class: 2, Tag: 0, IsCompound: true, Bytes: privateKeyBytes}
		resp.EncryptCerts = marshalCertificates(encryptCerts)
	}
	return asn1.Marshal(resp)
}

// concats and wraps the certificates in the RawValue structure
func marshalCertificates(certs []*Certificate) rawCertificates {
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
	var val = asn1.RawValue{Bytes: certs, Class: 2, Tag: 0, IsCompound: true}
	b, err := asn1.Marshal(val)
	if err != nil {
		return rawCertificates{}, err
	}
	return rawCertificates{Raw: b}, nil
}

func (raw rawCertificates) Parse() ([]*Certificate, error) {
	if len(raw.Raw) == 0 {
		return nil, nil
	}

	var val asn1.RawValue
	if _, err := asn1.Unmarshal(raw.Raw, &val); err != nil {
		return nil, err
	}

	return ParseCertificates(val.Bytes)
}
