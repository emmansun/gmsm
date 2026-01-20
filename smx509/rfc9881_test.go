// Copyright 2025 Sun Yimin. All rights reserved.
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file.

package smx509

import (
	"crypto/rand"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"testing"
	"time"

	"github.com/emmansun/gmsm/mldsa"
)

// TestRFC9881_C3_Style_MLDSA44_Certificate tests RFC 9881 Appendix C.3 style self-signed ML-DSA-44 certificate
// This test creates a self-signed certificate similar to the example in RFC 9881 C.3
// which demonstrates ML-DSA-44 signature algorithm with proper key usage bits
func TestRFC9881_C3_Style_MLDSA44_Certificate(t *testing.T) {
	// Generate ML-DSA-44 key pair
	priv, err := mldsa.GenerateKey44(rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate ML-DSA-44 key pair: %v", err)
	}
	pub := priv.Public()

	// Create a self-signed certificate template similar to RFC 9881 C.3
	// Note: RFC 9881 C.3 example has KeyUsage bits set to digitalSignature, keyCertSign, and cRLSign
	serialNumber, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	template := &Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{"IETF"},
			CommonName:   "Test ML-DSA-44 Root CA",
		},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              KeyUsageDigitalSignature | KeyUsageCertSign | KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            0,
		MaxPathLenZero:        true,
	}

	// Create self-signed certificate
	certDER, err := CreateCertificate(rand.Reader, template, template, pub, priv)
	if err != nil {
		t.Fatalf("Failed to create self-signed certificate: %v", err)
	}

	// Parse the created certificate
	cert, err := ParseCertificate(certDER)
	if err != nil {
		t.Fatalf("Failed to parse certificate: %v", err)
	}

	// Verify the signature algorithm is ML-DSA-44 as per RFC 9881
	if cert.SignatureAlgorithm != MLDSA44 {
		t.Errorf("Expected signature algorithm MLDSA44 (OID 2.16.840.1.101.3.4.3.17), got %v", cert.SignatureAlgorithm)
	}

	// Verify the public key algorithm
	if cert.PublicKeyAlgorithm != PKMLDSA44 {
		t.Errorf("Expected public key algorithm PKMLDSA44 (OID 2.16.840.1.101.3.4.3.17), got %v", cert.PublicKeyAlgorithm)
	}

	// Verify the certificate is self-signed
	if cert.Issuer.String() != cert.Subject.String() {
		t.Errorf("Certificate is not self-signed: Issuer=%v, Subject=%v", cert.Issuer, cert.Subject)
	}

	// Verify the self-signed certificate signature
	if err := cert.CheckSignatureFrom(cert); err != nil {
		t.Errorf("Failed to verify self-signed certificate signature: %v", err)
	}

	// Verify key usage as per RFC 9881 C.3 example
	// The RFC example has digitalSignature, keyCertSign, and cRLSign
	if cert.KeyUsage&KeyUsageDigitalSignature == 0 {
		t.Error("Expected KeyUsageDigitalSignature to be set per RFC 9881 C.3")
	}
	if cert.KeyUsage&KeyUsageCertSign == 0 {
		t.Error("Expected KeyUsageCertSign to be set per RFC 9881 C.3")
	}
	if cert.KeyUsage&KeyUsageCRLSign == 0 {
		t.Error("Expected KeyUsageCRLSign to be set per RFC 9881 C.3")
	}

	// Verify this is a CA certificate
	if !cert.IsCA {
		t.Error("Expected certificate to be a CA certificate per RFC 9881 C.3")
	}

	// Verify the subject organization is IETF (as in RFC 9881 C.3)
	if len(cert.Subject.Organization) == 0 || cert.Subject.Organization[0] != "IETF" {
		t.Errorf("Expected organization to be IETF (as in RFC 9881 C.3), got %v", cert.Subject.Organization)
	}

	t.Log("RFC 9881 C.3 style ML-DSA-44 self-signed certificate successfully created and verified")
	t.Logf("Certificate uses OID 2.16.840.1.101.3.4.3.17 for ML-DSA-44 as specified in RFC 9881")
}

// TestRFC9881_C3_Style_MLDSA65_Certificate tests RFC 9881 style self-signed ML-DSA-65 certificate
func TestRFC9881_C3_Style_MLDSA65_Certificate(t *testing.T) {
	priv, err := mldsa.GenerateKey65(rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate ML-DSA-65 key pair: %v", err)
	}
	pub := priv.Public()

	serialNumber, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	template := &Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{"IETF"},
			CommonName:   "Test ML-DSA-65 Root CA",
		},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              KeyUsageDigitalSignature | KeyUsageCertSign | KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            0,
		MaxPathLenZero:        true,
	}

	certDER, err := CreateCertificate(rand.Reader, template, template, pub, priv)
	if err != nil {
		t.Fatalf("Failed to create self-signed certificate: %v", err)
	}

	cert, err := ParseCertificate(certDER)
	if err != nil {
		t.Fatalf("Failed to parse certificate: %v", err)
	}

	if cert.SignatureAlgorithm != MLDSA65 {
		t.Errorf("Expected signature algorithm MLDSA65 (OID 2.16.840.1.101.3.4.3.18), got %v", cert.SignatureAlgorithm)
	}

	if cert.PublicKeyAlgorithm != PKMLDSA65 {
		t.Errorf("Expected public key algorithm PKMLDSA65, got %v", cert.PublicKeyAlgorithm)
	}

	if err := cert.CheckSignatureFrom(cert); err != nil {
		t.Errorf("Failed to verify self-signed certificate signature: %v", err)
	}

	t.Log("RFC 9881 style ML-DSA-65 self-signed certificate successfully created and verified")
	t.Logf("Certificate uses OID 2.16.840.1.101.3.4.3.18 for ML-DSA-65 as specified in RFC 9881")
}

// TestRFC9881_C3_Style_MLDSA87_Certificate tests RFC 9881 style self-signed ML-DSA-87 certificate
func TestRFC9881_C3_Style_MLDSA87_Certificate(t *testing.T) {
	priv, err := mldsa.GenerateKey87(rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate ML-DSA-87 key pair: %v", err)
	}
	pub := priv.Public()

	serialNumber, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	template := &Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{"IETF"},
			CommonName:   "Test ML-DSA-87 Root CA",
		},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              KeyUsageDigitalSignature | KeyUsageCertSign | KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            0,
		MaxPathLenZero:        true,
	}

	certDER, err := CreateCertificate(rand.Reader, template, template, pub, priv)
	if err != nil {
		t.Fatalf("Failed to create self-signed certificate: %v", err)
	}

	cert, err := ParseCertificate(certDER)
	if err != nil {
		t.Fatalf("Failed to parse certificate: %v", err)
	}

	if cert.SignatureAlgorithm != MLDSA87 {
		t.Errorf("Expected signature algorithm MLDSA87 (OID 2.16.840.1.101.3.4.3.19), got %v", cert.SignatureAlgorithm)
	}

	if cert.PublicKeyAlgorithm != PKMLDSA87 {
		t.Errorf("Expected public key algorithm PKMLDSA87, got %v", cert.PublicKeyAlgorithm)
	}

	if err := cert.CheckSignatureFrom(cert); err != nil {
		t.Errorf("Failed to verify self-signed certificate signature: %v", err)
	}

	t.Log("RFC 9881 style ML-DSA-87 self-signed certificate successfully created and verified")
	t.Logf("Certificate uses OID 2.16.840.1.101.3.4.3.19 for ML-DSA-87 as specified in RFC 9881")
}

// TestRFC9881_C3_MLDSA44_ExampleCertificate tests the actual ML-DSA-44 example certificate from RFC 9881 Appendix C.3
func TestRFC9881_C3_MLDSA44_ExampleCertificate(t *testing.T) {
	block, _ := pem.Decode([]byte(certRFC9881C3MLDSA44))
	if block == nil {
		t.Fatal("Failed to decode PEM certificate")
	}

	// Parse the certificate
	cert, err := ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("Failed to parse RFC 9881 C.3 ML-DSA-44 certificate: %v", err)
	}

	// Verify signature algorithm
	if cert.SignatureAlgorithm != MLDSA44 {
		t.Errorf("Expected signature algorithm MLDSA44, got %v", cert.SignatureAlgorithm)
	}

	// Verify public key algorithm
	if cert.PublicKeyAlgorithm != PKMLDSA44 {
		t.Errorf("Expected public key algorithm PKMLDSA44, got %v", cert.PublicKeyAlgorithm)
	}

	// Verify the certificate is self-signed (Issuer == Subject)
	if cert.Issuer.String() != cert.Subject.String() {
		t.Errorf("Certificate is not self-signed: Issuer=%v, Subject=%v", cert.Issuer, cert.Subject)
	}

	// Verify organization is IETF
	if len(cert.Subject.Organization) == 0 || cert.Subject.Organization[0] != "IETF" {
		t.Errorf("Expected organization IETF, got %v", cert.Subject.Organization)
	}

	// Verify common name is "LAMPS WG"
	if cert.Subject.CommonName != "LAMPS WG" {
		t.Errorf("Expected common name 'LAMPS WG', got %s", cert.Subject.CommonName)
	}

	// Verify key usage bits per RFC 9881 C.3
	if cert.KeyUsage&KeyUsageDigitalSignature == 0 {
		t.Error("Expected KeyUsageDigitalSignature to be set")
	}
	if cert.KeyUsage&KeyUsageCertSign == 0 {
		t.Error("Expected KeyUsageCertSign to be set")
	}
	if cert.KeyUsage&KeyUsageCRLSign == 0 {
		t.Error("Expected KeyUsageCRLSign to be set")
	}

	// Verify it's a CA certificate
	if !cert.IsCA {
		t.Error("Expected certificate to be a CA certificate")
	}

	// Verify the self-signed signature
	if err := cert.CheckSignatureFrom(cert); err != nil {
		t.Errorf("Failed to verify self-signed certificate signature: %v", err)
	}

	t.Log("Successfully parsed and verified RFC 9881 C.3 ML-DSA-44 example certificate")
}

// TestRFC9881_C3_MLDSA65_ExampleCertificate tests the actual ML-DSA-65 example certificate from RFC 9881 Appendix C.3
func TestRFC9881_C3_MLDSA65_ExampleCertificate(t *testing.T) {
	block, _ := pem.Decode([]byte(certRFC9881C3MLDSA65))
	if block == nil {
		t.Fatal("Failed to decode PEM certificate")
	}

	cert, err := ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("Failed to parse RFC 9881 C.3 ML-DSA-65 certificate: %v", err)
	}

	if cert.SignatureAlgorithm != MLDSA65 {
		t.Errorf("Expected signature algorithm MLDSA65, got %v", cert.SignatureAlgorithm)
	}

	if cert.PublicKeyAlgorithm != PKMLDSA65 {
		t.Errorf("Expected public key algorithm PKMLDSA65, got %v", cert.PublicKeyAlgorithm)
	}

	if cert.Issuer.String() != cert.Subject.String() {
		t.Errorf("Certificate is not self-signed: Issuer=%v, Subject=%v", cert.Issuer, cert.Subject)
	}

	if len(cert.Subject.Organization) == 0 || cert.Subject.Organization[0] != "IETF" {
		t.Errorf("Expected organization IETF, got %v", cert.Subject.Organization)
	}

	if cert.Subject.CommonName != "LAMPS WG" {
		t.Errorf("Expected common name 'LAMPS WG', got %s", cert.Subject.CommonName)
	}

	if cert.KeyUsage&KeyUsageDigitalSignature == 0 {
		t.Error("Expected KeyUsageDigitalSignature to be set")
	}
	if cert.KeyUsage&KeyUsageCertSign == 0 {
		t.Error("Expected KeyUsageCertSign to be set")
	}
	if cert.KeyUsage&KeyUsageCRLSign == 0 {
		t.Error("Expected KeyUsageCRLSign to be set")
	}

	if !cert.IsCA {
		t.Error("Expected certificate to be a CA certificate")
	}

	if err := cert.CheckSignatureFrom(cert); err != nil {
		t.Errorf("Failed to verify self-signed certificate signature: %v", err)
	}

	t.Log("Successfully parsed and verified RFC 9881 C.3 ML-DSA-65 example certificate")
}

// TestRFC9881_C3_MLDSA87_ExampleCertificate tests the actual ML-DSA-87 example certificate from RFC 9881 Appendix C.3
func TestRFC9881_C3_MLDSA87_ExampleCertificate(t *testing.T) {
	block, _ := pem.Decode([]byte(certRFC9881C3MLDSA87))
	if block == nil {
		t.Fatal("Failed to decode PEM certificate")
	}

	cert, err := ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("Failed to parse RFC 9881 C.3 ML-DSA-87 certificate: %v", err)
	}

	if cert.SignatureAlgorithm != MLDSA87 {
		t.Errorf("Expected signature algorithm MLDSA87, got %v", cert.SignatureAlgorithm)
	}

	if cert.PublicKeyAlgorithm != PKMLDSA87 {
		t.Errorf("Expected public key algorithm PKMLDSA87, got %v", cert.PublicKeyAlgorithm)
	}

	if cert.Issuer.String() != cert.Subject.String() {
		t.Errorf("Certificate is not self-signed: Issuer=%v, Subject=%v", cert.Issuer, cert.Subject)
	}

	if len(cert.Subject.Organization) == 0 || cert.Subject.Organization[0] != "IETF" {
		t.Errorf("Expected organization IETF, got %v", cert.Subject.Organization)
	}

	if cert.Subject.CommonName != "LAMPS WG" {
		t.Errorf("Expected common name 'LAMPS WG', got %s", cert.Subject.CommonName)
	}

	if cert.KeyUsage&KeyUsageDigitalSignature == 0 {
		t.Error("Expected KeyUsageDigitalSignature to be set")
	}
	if cert.KeyUsage&KeyUsageCertSign == 0 {
		t.Error("Expected KeyUsageCertSign to be set")
	}
	if cert.KeyUsage&KeyUsageCRLSign == 0 {
		t.Error("Expected KeyUsageCRLSign to be set")
	}

	if !cert.IsCA {
		t.Error("Expected certificate to be a CA certificate")
	}

	if err := cert.CheckSignatureFrom(cert); err != nil {
		t.Errorf("Failed to verify self-signed certificate signature: %v", err)
	}

	t.Log("Successfully parsed and verified RFC 9881 C.3 ML-DSA-87 example certificate")
}

var certRFC9881C3MLDSA44 = `
-----BEGIN CERTIFICATE-----
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
AAAAABcmOEM=
-----END CERTIFICATE-----
`

var certRFC9881C3MLDSA65 = `
-----BEGIN CERTIFICATE-----
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
IA==
-----END CERTIFICATE-----
`

var certRFC9881C3MLDSA87 = `
-----BEGIN CERTIFICATE-----
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
-----END CERTIFICATE-----
`
