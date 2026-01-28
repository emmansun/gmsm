package smx509

import (
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"

	"github.com/emmansun/gmsm/mldsa"
)

func TestMLDSA44Certificate(t *testing.T) {
	// Generate ML-DSA-44 key pair
	priv, err := mldsa.GenerateKey44(rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate ML-DSA-44 key: %v", err)
	}

	// Create certificate template
	template := &Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{"Test Org"},
			CommonName:   "ML-DSA-44 Test",
		},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              KeyUsageDigitalSignature | KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	// Create self-signed certificate
	certDER, err := CreateCertificate(rand.Reader, template, template, priv.Public(), priv)
	if err != nil {
		t.Fatalf("Failed to create ML-DSA-44 certificate: %v", err)
	}

	// Parse the certificate
	cert, err := ParseCertificate(certDER)
	if err != nil {
		t.Fatalf("Failed to parse ML-DSA-44 certificate: %v", err)
	}

	// Verify the certificate signature algorithm
	if cert.SignatureAlgorithm != MLDSA44 {
		t.Errorf("Expected signature algorithm MLDSA44, got %v", cert.SignatureAlgorithm)
	}

	// Verify the public key algorithm
	if cert.PublicKeyAlgorithm != PKMLDSA44 {
		t.Errorf("Expected public key algorithm PKMLDSA44, got %v", cert.PublicKeyAlgorithm)
	}

	// Verify the public key type
	pubKey, ok := cert.PublicKey.(*mldsa.PublicKey44)
	if !ok {
		t.Fatalf("Expected *mldsa.PublicKey44, got %T", cert.PublicKey)
	}

	// Verify the public key matches
	if !priv.Public().(*mldsa.PublicKey44).Equal(pubKey) {
		t.Error("Public key in certificate doesn't match generated key")
	}

	// Verify the certificate signature
	if err := cert.CheckSignatureFrom(cert); err != nil {
		t.Fatalf("Certificate signature verification failed: %v", err)
	}
}

func TestMLDSA65Certificate(t *testing.T) {
	// Generate ML-DSA-65 key pair
	priv, err := mldsa.GenerateKey65(rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate ML-DSA-65 key: %v", err)
	}

	// Create certificate template
	template := &Certificate{
		SerialNumber: big.NewInt(2),
		Subject: pkix.Name{
			Organization: []string{"Test Org"},
			CommonName:   "ML-DSA-65 Test",
		},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              KeyUsageDigitalSignature | KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	// Create self-signed certificate
	certDER, err := CreateCertificate(rand.Reader, template, template, priv.Public(), priv)
	if err != nil {
		t.Fatalf("Failed to create ML-DSA-65 certificate: %v", err)
	}

	// Parse the certificate
	cert, err := ParseCertificate(certDER)
	if err != nil {
		t.Fatalf("Failed to parse ML-DSA-65 certificate: %v", err)
	}

	// Verify the certificate signature algorithm
	if cert.SignatureAlgorithm != MLDSA65 {
		t.Errorf("Expected signature algorithm MLDSA65, got %v", cert.SignatureAlgorithm)
	}

	// Verify the public key algorithm
	if cert.PublicKeyAlgorithm != PKMLDSA65 {
		t.Errorf("Expected public key algorithm PKMLDSA65, got %v", cert.PublicKeyAlgorithm)
	}

	// Verify the public key type
	pubKey, ok := cert.PublicKey.(*mldsa.PublicKey65)
	if !ok {
		t.Fatalf("Expected *mldsa.PublicKey65, got %T", cert.PublicKey)
	}

	// Verify the public key matches
	if !priv.Public().(*mldsa.PublicKey65).Equal(pubKey) {
		t.Error("Public key in certificate doesn't match generated key")
	}

	// Verify the certificate signature
	if err := cert.CheckSignatureFrom(cert); err != nil {
		t.Fatalf("Certificate signature verification failed: %v", err)
	}
}

func TestMLDSA87Certificate(t *testing.T) {
	// Generate ML-DSA-87 key pair
	priv, err := mldsa.GenerateKey87(rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate ML-DSA-87 key: %v", err)
	}

	// Create certificate template
	template := &Certificate{
		SerialNumber: big.NewInt(3),
		Subject: pkix.Name{
			Organization: []string{"Test Org"},
			CommonName:   "ML-DSA-87 Test",
		},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              KeyUsageDigitalSignature | KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	// Create self-signed certificate
	certDER, err := CreateCertificate(rand.Reader, template, template, priv.Public(), priv)
	if err != nil {
		t.Fatalf("Failed to create ML-DSA-87 certificate: %v", err)
	}

	// Parse the certificate
	cert, err := ParseCertificate(certDER)
	if err != nil {
		t.Fatalf("Failed to parse ML-DSA-87 certificate: %v", err)
	}

	// Verify the certificate signature algorithm
	if cert.SignatureAlgorithm != MLDSA87 {
		t.Errorf("Expected signature algorithm MLDSA87, got %v", cert.SignatureAlgorithm)
	}

	// Verify the public key algorithm
	if cert.PublicKeyAlgorithm != PKMLDSA87 {
		t.Errorf("Expected public key algorithm PKMLDSA87, got %v", cert.PublicKeyAlgorithm)
	}

	// Verify the public key type
	pubKey, ok := cert.PublicKey.(*mldsa.PublicKey87)
	if !ok {
		t.Fatalf("Expected *mldsa.PublicKey87, got %T", cert.PublicKey)
	}

	// Verify the public key matches
	if !priv.Public().(*mldsa.PublicKey87).Equal(pubKey) {
		t.Error("Public key in certificate doesn't match generated key")
	}

	// Verify the certificate signature
	if err := cert.CheckSignatureFrom(cert); err != nil {
		t.Fatalf("Certificate signature verification failed: %v", err)
	}
}

func TestMLDSACertificateChain(t *testing.T) {
	// Generate CA key (ML-DSA-65)
	caPriv, err := mldsa.GenerateKey65(rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate CA key: %v", err)
	}

	// Create CA certificate
	caTemplate := &Certificate{
		SerialNumber: big.NewInt(100),
		Subject: pkix.Name{
			Organization: []string{"Test CA"},
			CommonName:   "ML-DSA CA",
		},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              KeyUsageCertSign | KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            1,
	}

	caCertDER, err := CreateCertificate(rand.Reader, caTemplate, caTemplate, caPriv.Public(), caPriv)
	if err != nil {
		t.Fatalf("Failed to create CA certificate: %v", err)
	}

	caCert, err := ParseCertificate(caCertDER)
	if err != nil {
		t.Fatalf("Failed to parse CA certificate: %v", err)
	}

	// Generate end-entity key (ML-DSA-44)
	eePriv, err := mldsa.GenerateKey44(rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate end-entity key: %v", err)
	}

	// Create end-entity certificate signed by CA
	eeTemplate := &Certificate{
		SerialNumber: big.NewInt(101),
		Subject: pkix.Name{
			Organization: []string{"Test Org"},
			CommonName:   "ML-DSA End Entity",
		},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(90 * 24 * time.Hour),
		KeyUsage:              KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  false,
	}

	eeCertDER, err := CreateCertificate(rand.Reader, eeTemplate, caTemplate, eePriv.Public(), caPriv)
	if err != nil {
		t.Fatalf("Failed to create end-entity certificate: %v", err)
	}

	eeCert, err := ParseCertificate(eeCertDER)
	if err != nil {
		t.Fatalf("Failed to parse end-entity certificate: %v", err)
	}

	// Verify end-entity certificate with CA
	if err := eeCert.CheckSignatureFrom(caCert); err != nil {
		t.Fatalf("End-entity certificate verification failed: %v", err)
	}

	// Verify signature algorithms
	if caCert.SignatureAlgorithm != MLDSA65 {
		t.Errorf("CA certificate: expected MLDSA65, got %v", caCert.SignatureAlgorithm)
	}
	if eeCert.SignatureAlgorithm != MLDSA65 {
		t.Errorf("EE certificate: expected MLDSA65 (signed by CA), got %v", eeCert.SignatureAlgorithm)
	}
	if eeCert.PublicKeyAlgorithm != PKMLDSA44 {
		t.Errorf("EE certificate public key: expected PKMLDSA44, got %v", eeCert.PublicKeyAlgorithm)
	}
}

func TestMLDSAPublicKeyMarshaling(t *testing.T) {
	tests := []struct {
		name     string
		generate func() (any, error)
	}{
		{"ML-DSA-44", func() (any, error) {
			priv, err := mldsa.GenerateKey44(rand.Reader)
			if err != nil {
				return nil, err
			}
			return priv.Public(), nil
		}},
		{"ML-DSA-65", func() (any, error) {
			priv, err := mldsa.GenerateKey65(rand.Reader)
			if err != nil {
				return nil, err
			}
			return priv.Public(), nil
		}},
		{"ML-DSA-87", func() (any, error) {
			priv, err := mldsa.GenerateKey87(rand.Reader)
			if err != nil {
				return nil, err
			}
			return priv.Public(), nil
		}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pub, err := tt.generate()
			if err != nil {
				t.Fatalf("Failed to generate key: %v", err)
			}

			// Marshal to PKIX format
			der, err := MarshalPKIXPublicKey(pub)
			if err != nil {
				t.Fatalf("Failed to marshal public key: %v", err)
			}

			// Parse back
			parsedPub, err := ParsePKIXPublicKey(der)
			if err != nil {
				t.Fatalf("Failed to parse public key: %v", err)
			}

			// Verify they match
			type equalable interface {
				Equal(crypto.PublicKey) bool
			}

			if eq, ok := pub.(equalable); !ok {
				t.Fatal("Public key doesn't implement Equal method")
			} else if !eq.Equal(parsedPub) {
				t.Error("Parsed public key doesn't match original")
			}

			// Re-marshal and verify DER encoding is stable
			der2, err := MarshalPKIXPublicKey(parsedPub)
			if err != nil {
				t.Fatalf("Failed to re-marshal public key: %v", err)
			}

			if string(der) != string(der2) {
				t.Error("DER encoding is not stable")
			}
		})
	}
}

func TestCreateMLDSA44CertificateRequest(t *testing.T) {
	// Generate ML-DSA-44 key pair
	priv, err := mldsa.GenerateKey44(rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate ML-DSA-44 key: %v", err)
	}

	// Create CSR template
	template := &x509.CertificateRequest{
		Subject: pkix.Name{
			CommonName:   "ML-DSA-44 CSR Test",
			Organization: []string{"Test Org"},
		},
		DNSNames:       []string{"example.com", "www.example.com"},
		EmailAddresses: []string{"test@example.com"},
	}

	// Create CSR
	csrDER, err := CreateCertificateRequest(rand.Reader, template, priv)
	if err != nil {
		t.Fatalf("Failed to create ML-DSA-44 CSR: %v", err)
	}

	// Parse the CSR
	csr, err := ParseCertificateRequest(csrDER)
	if err != nil {
		t.Fatalf("Failed to parse ML-DSA-44 CSR: %v", err)
	}

	// Verify the signature algorithm
	if csr.SignatureAlgorithm != MLDSA44 {
		t.Errorf("Expected signature algorithm MLDSA44, got %v", csr.SignatureAlgorithm)
	}

	// Verify the public key algorithm
	if csr.PublicKeyAlgorithm != PKMLDSA44 {
		t.Errorf("Expected public key algorithm PKMLDSA44, got %v", csr.PublicKeyAlgorithm)
	}

	// Verify the public key type
	pubKey, ok := csr.PublicKey.(*mldsa.PublicKey44)
	if !ok {
		t.Fatalf("Expected *mldsa.PublicKey44, got %T", csr.PublicKey)
	}

	// Verify the public key matches
	if !priv.Public().(*mldsa.PublicKey44).Equal(pubKey) {
		t.Error("Public key in CSR doesn't match generated key")
	}

	// Verify the CSR signature
	if err := csr.CheckSignature(); err != nil {
		t.Fatalf("CSR signature verification failed: %v", err)
	}

	// Verify subject
	if csr.Subject.CommonName != template.Subject.CommonName {
		t.Errorf("Subject CommonName mismatch: got %v, want %v", csr.Subject.CommonName, template.Subject.CommonName)
	}
}

func TestCreateMLDSA65CertificateRequest(t *testing.T) {
	// Generate ML-DSA-65 key pair
	priv, err := mldsa.GenerateKey65(rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate ML-DSA-65 key: %v", err)
	}

	// Create CSR template
	template := &x509.CertificateRequest{
		Subject: pkix.Name{
			CommonName:   "ML-DSA-65 CSR Test",
			Organization: []string{"Test Org"},
		},
	}

	// Create CSR
	csrDER, err := CreateCertificateRequest(rand.Reader, template, priv)
	if err != nil {
		t.Fatalf("Failed to create ML-DSA-65 CSR: %v", err)
	}

	// Parse the CSR
	csr, err := ParseCertificateRequest(csrDER)
	if err != nil {
		t.Fatalf("Failed to parse ML-DSA-65 CSR: %v", err)
	}

	// Verify the signature algorithm
	if csr.SignatureAlgorithm != MLDSA65 {
		t.Errorf("Expected signature algorithm MLDSA65, got %v", csr.SignatureAlgorithm)
	}

	// Verify the public key algorithm
	if csr.PublicKeyAlgorithm != PKMLDSA65 {
		t.Errorf("Expected public key algorithm PKMLDSA65, got %v", csr.PublicKeyAlgorithm)
	}

	// Verify the CSR signature
	if err := csr.CheckSignature(); err != nil {
		t.Fatalf("CSR signature verification failed: %v", err)
	}
}

func TestCreateMLDSA87CertificateRequest(t *testing.T) {
	// Generate ML-DSA-87 key pair
	priv, err := mldsa.GenerateKey87(rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate ML-DSA-87 key: %v", err)
	}

	// Create CSR template
	template := &x509.CertificateRequest{
		Subject: pkix.Name{
			CommonName:   "ML-DSA-87 CSR Test",
			Organization: []string{"Test Org"},
		},
	}

	// Create CSR
	csrDER, err := CreateCertificateRequest(rand.Reader, template, priv)
	if err != nil {
		t.Fatalf("Failed to create ML-DSA-87 CSR: %v", err)
	}

	// Parse the CSR
	csr, err := ParseCertificateRequest(csrDER)
	if err != nil {
		t.Fatalf("Failed to parse ML-DSA-87 CSR: %v", err)
	}

	// Verify the signature algorithm
	if csr.SignatureAlgorithm != MLDSA87 {
		t.Errorf("Expected signature algorithm MLDSA87, got %v", csr.SignatureAlgorithm)
	}

	// Verify the public key algorithm
	if csr.PublicKeyAlgorithm != PKMLDSA87 {
		t.Errorf("Expected public key algorithm PKMLDSA87, got %v", csr.PublicKeyAlgorithm)
	}

	// Verify the CSR signature
	if err := csr.CheckSignature(); err != nil {
		t.Fatalf("CSR signature verification failed: %v", err)
	}
}

func TestCreateMLDSA44RevocationList(t *testing.T) {
	// Generate CA key (ML-DSA-44)
	caPriv, err := mldsa.GenerateKey44(rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate CA key: %v", err)
	}

	// Create CA certificate
	caTemplate := &Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName:   "ML-DSA-44 CA",
			Organization: []string{"Test CA"},
		},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              KeyUsageCertSign | KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	caCertDER, err := CreateCertificate(rand.Reader, caTemplate, caTemplate, caPriv.Public(), caPriv)
	if err != nil {
		t.Fatalf("Failed to create CA certificate: %v", err)
	}

	caCert, err := ParseCertificate(caCertDER)
	if err != nil {
		t.Fatalf("Failed to parse CA certificate: %v", err)
	}

	// Create CRL template
	now := time.Now()
	revokedCerts := []x509.RevocationListEntry{
		{
			SerialNumber:   big.NewInt(100),
			RevocationTime: now.Add(-24 * time.Hour),
			ReasonCode:     1, // keyCompromise
		},
		{
			SerialNumber:   big.NewInt(101),
			RevocationTime: now.Add(-12 * time.Hour),
			ReasonCode:     3, // affiliationChanged
		},
	}

	crlTemplate := &x509.RevocationList{
		Number:                    big.NewInt(1),
		ThisUpdate:                now,
		NextUpdate:                now.Add(7 * 24 * time.Hour),
		RevokedCertificateEntries: revokedCerts,
	}

	// Create CRL
	crlDER, err := CreateRevocationList(rand.Reader, crlTemplate, caCert, caPriv)
	if err != nil {
		t.Fatalf("Failed to create ML-DSA-44 CRL: %v", err)
	}

	// Parse the CRL
	crl, err := ParseRevocationList(crlDER)
	if err != nil {
		t.Fatalf("Failed to parse ML-DSA-44 CRL: %v", err)
	}

	// Verify the signature algorithm
	if crl.SignatureAlgorithm != MLDSA44 {
		t.Errorf("Expected signature algorithm MLDSA44, got %v", crl.SignatureAlgorithm)
	}

	// Verify revoked certificates count
	if len(crl.RevokedCertificateEntries) != len(revokedCerts) {
		t.Errorf("Expected %d revoked certificates, got %d", len(revokedCerts), len(crl.RevokedCertificateEntries))
	}

	// Verify CRL signature using our wrapper
	if err := crl.CheckSignatureFrom(caCert); err != nil {
		t.Fatalf("CRL signature verification failed: %v", err)
	}
}

func TestCreateMLDSA65RevocationList(t *testing.T) {
	// Generate CA key (ML-DSA-65)
	caPriv, err := mldsa.GenerateKey65(rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate CA key: %v", err)
	}

	// Create CA certificate
	caTemplate := &Certificate{
		SerialNumber: big.NewInt(2),
		Subject: pkix.Name{
			CommonName:   "ML-DSA-65 CA",
			Organization: []string{"Test CA"},
		},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              KeyUsageCertSign | KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	caCertDER, err := CreateCertificate(rand.Reader, caTemplate, caTemplate, caPriv.Public(), caPriv)
	if err != nil {
		t.Fatalf("Failed to create CA certificate: %v", err)
	}

	caCert, err := ParseCertificate(caCertDER)
	if err != nil {
		t.Fatalf("Failed to parse CA certificate: %v", err)
	}

	// Create CRL template
	now := time.Now()
	crlTemplate := &x509.RevocationList{
		Number:     big.NewInt(1),
		ThisUpdate: now,
		NextUpdate: now.Add(7 * 24 * time.Hour),
	}

	// Create CRL
	crlDER, err := CreateRevocationList(rand.Reader, crlTemplate, caCert, caPriv)
	if err != nil {
		t.Fatalf("Failed to create ML-DSA-65 CRL: %v", err)
	}

	// Parse the CRL
	crl, err := ParseRevocationList(crlDER)
	if err != nil {
		t.Fatalf("Failed to parse ML-DSA-65 CRL: %v", err)
	}

	// Verify the signature algorithm
	if crl.SignatureAlgorithm != MLDSA65 {
		t.Errorf("Expected signature algorithm MLDSA65, got %v", crl.SignatureAlgorithm)
	}

	// Verify CRL signature
	if err := crl.CheckSignatureFrom(caCert); err != nil {
		t.Fatalf("CRL signature verification failed: %v", err)
	}
}

func TestCreateMLDSA87RevocationList(t *testing.T) {
	// Generate CA key (ML-DSA-87)
	caPriv, err := mldsa.GenerateKey87(rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate CA key: %v", err)
	}

	// Create CA certificate
	caTemplate := &Certificate{
		SerialNumber: big.NewInt(3),
		Subject: pkix.Name{
			CommonName:   "ML-DSA-87 CA",
			Organization: []string{"Test CA"},
		},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              KeyUsageCertSign | KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	caCertDER, err := CreateCertificate(rand.Reader, caTemplate, caTemplate, caPriv.Public(), caPriv)
	if err != nil {
		t.Fatalf("Failed to create CA certificate: %v", err)
	}

	caCert, err := ParseCertificate(caCertDER)
	if err != nil {
		t.Fatalf("Failed to parse CA certificate: %v", err)
	}

	// Create CRL template
	now := time.Now()
	crlTemplate := &x509.RevocationList{
		Number:     big.NewInt(1),
		ThisUpdate: now,
		NextUpdate: now.Add(7 * 24 * time.Hour),
	}

	// Create CRL
	crlDER, err := CreateRevocationList(rand.Reader, crlTemplate, caCert, caPriv)
	if err != nil {
		t.Fatalf("Failed to create ML-DSA-87 CRL: %v", err)
	}

	// Parse the CRL
	crl, err := ParseRevocationList(crlDER)
	if err != nil {
		t.Fatalf("Failed to parse ML-DSA-87 CRL: %v", err)
	}

	// Verify the signature algorithm
	if crl.SignatureAlgorithm != MLDSA87 {
		t.Errorf("Expected signature algorithm MLDSA87, got %v", crl.SignatureAlgorithm)
	}

	// Verify CRL signature
	if err := crl.CheckSignatureFrom(caCert); err != nil {
		t.Fatalf("CRL signature verification failed: %v", err)
	}
}
