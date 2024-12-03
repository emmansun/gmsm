// Copyright 2024 Sun Yimin. All rights reserved.
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file.

package cfca

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"math/big"
	"testing"
	"time"

	"github.com/emmansun/gmsm/pkcs"
	"github.com/emmansun/gmsm/sm2"
	"github.com/emmansun/gmsm/smx509"
)

type certKeyPair struct {
	Certificate *smx509.Certificate
	PrivateKey  *crypto.PrivateKey
}

func createTestSM2Certificate(allCA bool) (certKeyPair, error) {
	signer, err := createTestSM2CertificateByIssuer("Eddard Stark", nil, smx509.SM2WithSM3, true)
	if err != nil {
		return certKeyPair{}, err
	}
	pair, err := createTestSM2CertificateByIssuer("Jon Snow", signer, smx509.SM2WithSM3, allCA)
	if err != nil {
		return certKeyPair{}, err
	}
	return *pair, nil
}

func createTestSM2CertificateByIssuer(name string, issuer *certKeyPair, sigAlg x509.SignatureAlgorithm, isCA bool) (*certKeyPair, error) {
	var (
		err        error
		priv       crypto.PrivateKey
		derCert    []byte
		issuerCert *smx509.Certificate
		issuerKey  crypto.PrivateKey
	)
	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 32)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return nil, err
	}

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName:   name,
			Organization: []string{"Acme Co"},
		},
		NotBefore:   time.Now().Add(-1 * time.Second),
		NotAfter:    time.Now().AddDate(1, 0, 0),
		KeyUsage:    x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageEmailProtection},
	}
	if issuer != nil {
		issuerCert = issuer.Certificate
		issuerKey = *issuer.PrivateKey
	}

	switch sigAlg {
	case smx509.SM2WithSM3:
		priv, err = sm2.GenerateKey(rand.Reader)
		if err != nil {
			return nil, err
		}
	default:
		return nil, fmt.Errorf("unsupported signature algorithm %v", sigAlg)
	}
	if isCA {
		template.IsCA = true
		template.KeyUsage |= x509.KeyUsageCertSign
		template.BasicConstraintsValid = true
	}
	if issuer == nil {
		// no issuer given,make this a self-signed root cert
		issuerCert = (*smx509.Certificate)(&template)
		issuerKey = priv
	}

	switch pkey := priv.(type) {
	case *sm2.PrivateKey:
		derCert, err = smx509.CreateCertificate(rand.Reader, &template, (*x509.Certificate)(issuerCert), pkey.Public(), issuerKey)
	default:
		return nil, fmt.Errorf("unsupported private key type %T", pkey)
	}
	if err != nil {
		return nil, err
	}
	if len(derCert) == 0 {
		return nil, fmt.Errorf("no certificate created, probably due to wrong keys. types were %T and %T", priv, issuerKey)
	}
	cert, err := smx509.ParseCertificate(derCert)
	if err != nil {
		return nil, err
	}
	// pem.Encode(os.Stdout, &pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})
	return &certKeyPair{
		Certificate: cert,
		PrivateKey:  &priv,
	}, nil
}

func TestEnvelopeMessage(t *testing.T) {
	ciphers := []pkcs.Cipher{
		pkcs.SM4,
		pkcs.SM4CBC,
	}
	for _, cipher := range ciphers {
		plaintext := []byte("Hello Secret World!")
		cert, err := createTestSM2Certificate(true)
		if err != nil {
			t.Fatal(err)
		}
		encrypted, err := EnvelopeMessage(cipher, plaintext, []*smx509.Certificate{cert.Certificate})
		if err != nil {
			t.Fatal(err)
		}
		_, err = OpenEnvelopedMessage(encrypted[:len(encrypted)-1], cert.Certificate, *cert.PrivateKey)
		if err == nil {
			t.Fatalf("expected error when decrypting with wrong key, got nil")
		}
		// pem.Encode(os.Stdout, &pem.Block{Type: "PKCS7", Bytes: encrypted})
		result, err := OpenEnvelopedMessage(encrypted, cert.Certificate, *cert.PrivateKey)
		if err != nil {
			t.Fatalf("cannot Decrypt encrypted result: %v", err)
		}
		if !bytes.Equal(plaintext, result) {
			t.Errorf("encrypted data does not match plaintext:\n\tExpected: %s\n\tActual: %s", plaintext, result)
		}
	}
}

func TestEnvelopeMessageLegacy(t *testing.T) {
	ciphers := []pkcs.Cipher{
		pkcs.SM4,
		pkcs.SM4CBC,
	}
	for _, cipher := range ciphers {
		plaintext := []byte("Hello Secret World!")
		cert, err := createTestSM2Certificate(false)
		if err != nil {
			t.Fatal(err)
		}
		encrypted, err := EnvelopeMessageLegacy(cipher, plaintext, []*smx509.Certificate{cert.Certificate})
		if err != nil {
			t.Fatal(err)
		}
		_, err = OpenEnvelopedMessage(encrypted[:len(encrypted)-1], cert.Certificate, *cert.PrivateKey)
		if err == nil {
			t.Fatalf("expected error when decrypting with wrong key, got nil")
		}
		// pem.Encode(os.Stdout, &pem.Block{Type: "PKCS7", Bytes: encrypted})
		result, err := OpenEnvelopedMessageLegacy(encrypted, cert.Certificate, *cert.PrivateKey)
		if err != nil {
			t.Fatalf("cannot Decrypt encrypted result: %v", err)
		}
		if !bytes.Equal(plaintext, result) {
			t.Errorf("encrypted data does not match plaintext:\n\tExpected: %s\n\tActual: %s", plaintext, result)
		}
	}
}
