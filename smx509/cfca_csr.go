// Copyright 2024 Sun Yimin. All rights reserved.
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file.

package smx509

import (
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
	oidChallengePassword = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 7}
	oidTmpPublicKey      = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 63}
	tmpPublicKeyPrefix   = []byte{0, 0xb4, 0, 0, 0, 1, 0, 0}
)

// CreateCFCACertificateRequest creates a new CFCA certificate request based on a
// template. The following members of template are used:
//
//   - SignatureAlgorithm
//   - Subject
//
// The certPriv is the private key for the certificate, and the tmpPriv is the temporary private key for returning encryption key decryption.
// The challenge password is basically a shared-secret nonce between you and CFCA, embedded in the CSR,
// which the issuer may use to authenticate you should that ever be needed.
// The template is the certificate request template, we just use Subject now.
func CreateCFCACertificateRequest(rand io.Reader, template *x509.CertificateRequest, priv, tmpPriv any, challengePassword string) ([]byte, error) {
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
	if tmpPriv != nil {
		rawAttributes, err = buildTmpPublicKeyAttr(rawAttributes, tmpPriv)
		if err != nil {
			return nil, err
		}
		rawAttributes, err = buildChallengePasswordAttr(rawAttributes, challengePassword)
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

func buildTmpPublicKeyAttr(rawAttributes []asn1.RawValue, tmpPriv any) ([]asn1.RawValue, error) {
	key, ok := tmpPriv.(crypto.Signer)
	if !ok {
		return nil, errors.New("x509: tmp private key does not implement crypto.Signer")
	}
	var publicKeyBytes [136]byte
	copy(publicKeyBytes[:], tmpPublicKeyPrefix)
	pub := key.Public()
	if !sm2.IsSM2PublicKey(pub) {
		return nil, errors.New("x509: only SM2 public key is supported")
	}
	ecPub, _ := pub.(*ecdsa.PublicKey)
	ecPub.X.FillBytes(publicKeyBytes[8:40])
	ecPub.Y.FillBytes(publicKeyBytes[72:104])
	b, _ := asn1.Marshal(publicKeyBytes[:])
	attrKey := struct {
		Type  asn1.ObjectIdentifier
		Value asn1.RawValue
	}{
		Type:  oidTmpPublicKey,
		Value: asn1.RawValue{FullBytes: b},
	}
	b, err := asn1.Marshal(attrKey)
	if err != nil {
		return nil, err
	}
	var rawValue asn1.RawValue
	if _, err = asn1.Unmarshal(b, &rawValue); err != nil {
		return nil, err
	}

	return append(rawAttributes, rawValue), nil
}
