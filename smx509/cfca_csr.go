// Copyright 2024 Sun Yimin. All rights reserved.
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file.

package smx509

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"io"

	"github.com/emmansun/gmsm/sm2"
)

var (
	// The challengePassword attribute type specifies a password by which an
	// entity may request certificate revocation.
	// A challenge-password attribute must have a single attribute value.
	// It is a PKCS #9 OBJECT IDENTIFIER https://datatracker.ietf.org/doc/html/rfc2986#page-5
	// https://datatracker.ietf.org/doc/html/rfc2985#page-16
	oidChallengePassword = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 7}

	// The tmpPublicKey attribute type specifies a temporary public key for returning encryption key decryption.
	// A tmpPublicKey attribute must have a single attribute value.
	// It's NOT a standard OID, but used by CFCA.
	// cfca.sadk.org.bouncycastle.gmt.GMTPKCSObjectIdentifiers.pkcs_9_at_tempPublicKey
	oidTmpPublicKey = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 63}

	// tmpPublicKeyPrefix is the fixed prefix of the temporary public key attribute value.
	tmpPublicKeyPrefix = []byte{0, 0xb4, 0, 0, 0, 1, 0, 0}
)

// CreateCFCACertificateRequest creates a new CFCA certificate request based on a
// template. The following members of template are used:
//
//   - SignatureAlgorithm
//   - Subject
//
// The certPriv is the private key for the certificate, and the tmpPub is the temporary private key for returning encryption key decryption.
// The challenge password is basically a shared-secret nonce between you and CFCA, embedded in the CSR,
// which the issuer may use to authenticate you should that ever be needed.
// The template is the certificate request template, we just use Subject now.
func CreateCFCACertificateRequest(rand io.Reader, template *x509.CertificateRequest, priv, tmpPub any, challengePassword string) ([]byte, error) {
	key, ok := priv.(crypto.Signer)
	if !ok {
		return nil, errors.New("x509: certificate private key does not implement crypto.Signer")
	}
	signatureAlgorithm, algorithmIdentifier, err := signingParamsForKey(key, template.SignatureAlgorithm)
	if err != nil {
		return nil, err
	}

	var publicKeyBytes []byte
	var publicKeyAlgorithm pkix.AlgorithmIdentifier
	publicKeyBytes, publicKeyAlgorithm, err = marshalPublicKey(key.Public())
	if err != nil {
		return nil, err
	}

	var rawAttributes []asn1.RawValue
	// Add the temporary public key and challenge password if requested.
	if tmpPub != nil {
		if !sm2.IsSM2PublicKey(tmpPub) {
			return nil, errors.New("x509: only SM2 public key is supported")
		}
		rawAttributes, err = buildChallengePasswordAttr(rawAttributes, challengePassword)
		if err != nil {
			return nil, err
		}
		rawAttributes, err = buildTmpPublicKeyAttr(rawAttributes, tmpPub)
		if err != nil {
			return nil, err
		}
	}

	asn1Subject := template.RawSubject
	if len(asn1Subject) == 0 {
		asn1Subject, err = asn1.Marshal(template.Subject.ToRDNSequence())
		if err != nil {
			return nil, err
		}
	}

	tbsCSR := tbsCertificateRequest{
		Version: 0, // PKCS #10, RFC 2986
		Subject: asn1.RawValue{FullBytes: asn1Subject},
		PublicKey: publicKeyInfo{
			Algorithm: publicKeyAlgorithm,
			PublicKey: asn1.BitString{
				Bytes:     publicKeyBytes,
				BitLength: len(publicKeyBytes) * 8,
			},
		},
		RawAttributes: rawAttributes,
	}

	tbsCSRContents, err := asn1.Marshal(tbsCSR)
	if err != nil {
		return nil, err
	}
	tbsCSR.Raw = tbsCSRContents

	signature, err := signTBS(tbsCSRContents, key, signatureAlgorithm, rand)
	if err != nil {
		return nil, err
	}

	return asn1.Marshal(certificateRequest{
		TBSCSR:             tbsCSR,
		SignatureAlgorithm: algorithmIdentifier,
		SignatureValue: asn1.BitString{
			Bytes:     signature,
			BitLength: len(signature) * 8,
		},
	})
}

func buildChallengePasswordAttr(rawAttributes []asn1.RawValue, challengePassword string) ([]asn1.RawValue, error) {
	if len(challengePassword) == 0 {
		return nil, errors.New("x509: challenge password is required")
	}
	attr := struct {
		Type  asn1.ObjectIdentifier
		Value string
	}{
		Type:  oidChallengePassword,
		Value: challengePassword,
	}

	b, err := asn1.Marshal(attr)
	if err != nil {
		return nil, err
	}

	var rawValue asn1.RawValue
	if _, err := asn1.Unmarshal(b, &rawValue); err != nil {
		return nil, err
	}

	return append(rawAttributes, rawValue), nil
}

type tmpPublicKeyInfo struct {
	Version   int `asn1:"default:1"`
	PublicKey []byte
}

func buildTmpPublicKeyAttr(rawAttributes []asn1.RawValue, tmpPub crypto.PublicKey) ([]asn1.RawValue, error) {
	var publicKeyBytes [136]byte
	// Prefix{8} || X{32} || zero{32} || Y{32} || zero{32}
	copy(publicKeyBytes[:], tmpPublicKeyPrefix)
	ecPub, _ := tmpPub.(*ecdsa.PublicKey)
	ecPub.X.FillBytes(publicKeyBytes[8:40])
	ecPub.Y.FillBytes(publicKeyBytes[72:104])
	var tmpPublicKey = tmpPublicKeyInfo{
		Version:   1,
		PublicKey: publicKeyBytes[:],
	}
	b, err := asn1.Marshal(tmpPublicKey)
	if err != nil {
		return nil, err
	}
	attrKey := struct {
		Type  asn1.ObjectIdentifier
		Value []byte
	}{
		Type:  oidTmpPublicKey,
		Value: b,
	}
	b, err = asn1.Marshal(attrKey)
	if err != nil {
		return nil, err
	}
	var rawValue asn1.RawValue
	if _, err = asn1.Unmarshal(b, &rawValue); err != nil {
		return nil, err
	}

	return append(rawAttributes, rawValue), nil
}

// CertificateRequestCFCA represents a CFCA certificate request.
type CertificateRequestCFCA struct {
	CertificateRequest
	ChallengePassword string
	TmpPublicKey      any
}

// ParseCFCACertificateRequest parses a CFCA certificate request from the given DER data.
func ParseCFCACertificateRequest(asn1Data []byte) (*CertificateRequestCFCA, error) {
	var csr certificateRequest

	rest, err := asn1.Unmarshal(asn1Data, &csr)
	if err != nil {
		return nil, err
	} else if len(rest) != 0 {
		return nil, asn1.SyntaxError{Msg: "trailing data"}
	}

	inner, err := parseCertificateRequest(&csr)
	if err != nil {
		return nil, err
	}
	out := &CertificateRequestCFCA{
		CertificateRequest: *inner,
	}
	parseCFCAAttributes(out, csr.TBSCSR.RawAttributes)
	return out, nil
}

func parseCFCAAttributes(out *CertificateRequestCFCA, rawAttributes []asn1.RawValue) {
	var value struct {
		Type  asn1.ObjectIdentifier
		Value asn1.RawValue
	}
	for _, attr := range rawAttributes {
		if _, err := asn1.Unmarshal(attr.FullBytes, &value); err != nil {
			continue
		}
		switch {
		case value.Type.Equal(oidChallengePassword):
			asn1.Unmarshal(value.Value.FullBytes, &out.ChallengePassword)
		case value.Type.Equal(oidTmpPublicKey):
			var tmpPub tmpPublicKeyInfo
			if _, err := asn1.Unmarshal(value.Value.Bytes, &tmpPub); err != nil {
				continue
			}
			keyBytes := tmpPub.PublicKey
			if len(keyBytes) == 136 && bytes.Equal(tmpPublicKeyPrefix, keyBytes[:8]) {
				// parse the public key
				copy(keyBytes[40:72], keyBytes[72:104])
				out.TmpPublicKey, _ = sm2.NewPublicKey(keyBytes[8:72])
			}
		}
	}
}
