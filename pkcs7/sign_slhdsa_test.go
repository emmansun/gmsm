package pkcs7

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"math/big"
	"testing"
	"time"

	"github.com/emmansun/gmsm/slhdsa"
	"github.com/emmansun/gmsm/smx509"
)

// createSLHDSATestCertificate creates a test certificate with SLH-DSA signature algorithm
func createSLHDSATestCertificate(sigAlg smx509.SignatureAlgorithm, issuer *certKeyPair, isCA bool) (*certKeyPair, error) {
	var priv crypto.PrivateKey
	var err error

	// Generate SLH-DSA key pair based on signature algorithm
	switch sigAlg {
	case smx509.SLHDSASHA2128s:
		priv, err = slhdsa.SLHDSA128SmallSHA2.GenerateKey(rand.Reader)
	case smx509.SLHDSASHA2128f:
		priv, err = slhdsa.SLHDSA128FastSHA2.GenerateKey(rand.Reader)
	case smx509.SLHDSASHA2192s:
		priv, err = slhdsa.SLHDSA192SmallSHA2.GenerateKey(rand.Reader)
	case smx509.SLHDSASHA2192f:
		priv, err = slhdsa.SLHDSA192FastSHA2.GenerateKey(rand.Reader)
	case smx509.SLHDSASHA2256s:
		priv, err = slhdsa.SLHDSA256SmallSHA2.GenerateKey(rand.Reader)
	case smx509.SLHDSASHA2256f:
		priv, err = slhdsa.SLHDSA256FastSHA2.GenerateKey(rand.Reader)
	case smx509.SLHDSASHAKE128s:
		priv, err = slhdsa.SLHDSA128SmallSHAKE.GenerateKey(rand.Reader)
	case smx509.SLHDSASHAKE128f:
		priv, err = slhdsa.SLHDSA128FastSHAKE.GenerateKey(rand.Reader)
	case smx509.SLHDSASHAKE192s:
		priv, err = slhdsa.SLHDSA192SmallSHAKE.GenerateKey(rand.Reader)
	case smx509.SLHDSASHAKE192f:
		priv, err = slhdsa.SLHDSA192FastSHAKE.GenerateKey(rand.Reader)
	case smx509.SLHDSASHAKE256s:
		priv, err = slhdsa.SLHDSA256SmallSHAKE.GenerateKey(rand.Reader)
	case smx509.SLHDSASHAKE256f:
		priv, err = slhdsa.SLHDSA256FastSHAKE.GenerateKey(rand.Reader)
	default:
		return createTestCertificateByIssuer("SLH-DSA Test", issuer, x509.SignatureAlgorithm(sigAlg), isCA)
	}
	if err != nil {
		return nil, err
	}

	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 32)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return nil, err
	}

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName:   "SLH-DSA Test Certificate",
			Organization: []string{"Test Org"},
		},
		NotBefore:   time.Now().Add(-1 * time.Second),
		NotAfter:    time.Now().AddDate(1, 0, 0),
		KeyUsage:    x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageEmailProtection},
	}

	if isCA {
		template.IsCA = true
		template.KeyUsage |= x509.KeyUsageCertSign
		template.BasicConstraintsValid = true
	}

	var issuerCert *smx509.Certificate
	var issuerKey crypto.PrivateKey

	if issuer == nil {
		// Self-signed certificate
		issuerCert = (*smx509.Certificate)(&template)
		issuerKey = priv
	} else {
		issuerCert = issuer.Certificate
		issuerKey = *issuer.PrivateKey
	}

	// Get public key
	slhdsaPrivKey := priv.(*slhdsa.PrivateKey)
	pub := slhdsaPrivKey.Public()

	certBytes, err := smx509.CreateCertificate(rand.Reader, (*smx509.Certificate)(&template), issuerCert, pub, issuerKey)
	if err != nil {
		return nil, err
	}

	cert, err := smx509.ParseCertificate(certBytes)
	if err != nil {
		return nil, err
	}

	return &certKeyPair{
		Certificate: cert,
		PrivateKey:  &priv,
	}, nil
}

// TestSignSLHDSA tests signing with all SLH-DSA variants
func TestSignSLHDSA(t *testing.T) {
	content := []byte("Hello World")

	slhdsaVariants := []struct {
		name   string
		sigAlg smx509.SignatureAlgorithm
		hash   crypto.Hash
	}{
		{"SLH-DSA-SHA2-128s", smx509.SLHDSASHA2128s, crypto.SHA256},
		{"SLH-DSA-SHA2-128f", smx509.SLHDSASHA2128f, crypto.SHA256},
		{"SLH-DSA-SHA2-192s", smx509.SLHDSASHA2192s, crypto.SHA512},
		{"SLH-DSA-SHA2-192f", smx509.SLHDSASHA2192f, crypto.SHA512},
		{"SLH-DSA-SHA2-256s", smx509.SLHDSASHA2256s, crypto.SHA512},
		{"SLH-DSA-SHA2-256f", smx509.SLHDSASHA2256f, crypto.SHA512},
		{"SLH-DSA-SHAKE-128s", smx509.SLHDSASHAKE128s, crypto.SHA256},
		{"SLH-DSA-SHAKE-128f", smx509.SLHDSASHAKE128f, crypto.SHA256},
		{"SLH-DSA-SHAKE-192s", smx509.SLHDSASHAKE192s, crypto.SHA512},
		{"SLH-DSA-SHAKE-192f", smx509.SLHDSASHAKE192f, crypto.SHA512},
		{"SLH-DSA-SHAKE-256s", smx509.SLHDSASHAKE256s, crypto.SHA512},
		{"SLH-DSA-SHAKE-256f", smx509.SLHDSASHAKE256f, crypto.SHA512},
	}

	for _, variant := range slhdsaVariants {
		t.Run(variant.name, func(t *testing.T) {
			// Create SLH-DSA certificate
			signerCert, err := createSLHDSATestCertificate(variant.sigAlg, nil, false)
			if err != nil {
				t.Fatalf("Failed to create SLH-DSA certificate: %s", err)
			}

			// Create signed data
			toBeSigned, err := NewSignedData(content)
			if err != nil {
				t.Fatalf("Failed to create signed data: %s", err)
			}

			// Add signer with signed attributes
			if err := toBeSigned.AddSigner(signerCert.Certificate, *signerCert.PrivateKey, SignerInfoConfig{
				ExtraSignedAttributes: []Attribute{},
			}); err != nil {
				t.Fatalf("Failed to add signer: %s", err)
			}

			// Finish and get signature
			signed, err := toBeSigned.Finish()
			if err != nil {
				t.Fatalf("Failed to finish signed data: %s", err)
			}

			// Parse the signed data
			p7, err := Parse(signed)
			if err != nil {
				t.Fatalf("Failed to parse signed data: %s", err)
			}

			// Verify content
			if !bytes.Equal(p7.Content, content) {
				t.Errorf("Content mismatch:\n\tExpected: %s\n\tActual: %s", content, p7.Content)
			}

			// Verify signature
			if err := p7.Verify(); err != nil {
				t.Errorf("Failed to verify signature: %s", err)
			}

			// Check signer info
			if len(p7.Signers) != 1 {
				t.Fatalf("Expected 1 signer, got %d", len(p7.Signers))
			}

			// Verify authenticated attributes are present
			if len(p7.Signers[0].AuthenticatedAttributes) == 0 {
				t.Error("Expected authenticated attributes to be present")
			}
		})
	}
}

// TestSignSLHDSAWithoutAttrRejection tests that SignWithoutAttr properly rejects SLH-DSA keys
func TestSignSLHDSAWithoutAttrRejection(t *testing.T) {
	content := []byte("Hello World")

	slhdsaVariants := []struct {
		name   string
		sigAlg smx509.SignatureAlgorithm
	}{
		{"SLH-DSA-SHA2-128s", smx509.SLHDSASHA2128s},
		{"SLH-DSA-SHA2-256f", smx509.SLHDSASHA2256f},
		{"SLH-DSA-SHAKE-192s", smx509.SLHDSASHAKE192s},
	}

	for _, variant := range slhdsaVariants {
		t.Run(variant.name, func(t *testing.T) {
			// Create SLH-DSA certificate
			signerCert, err := createSLHDSATestCertificate(variant.sigAlg, nil, false)
			if err != nil {
				t.Fatalf("Failed to create SLH-DSA certificate: %s", err)
			}

			// Create signed data
			toBeSigned, err := NewSignedData(content)
			if err != nil {
				t.Fatalf("Failed to create signed data: %s", err)
			}

			// Attempt to sign without attributes - should fail
			err = toBeSigned.SignWithoutAttr(signerCert.Certificate, *signerCert.PrivateKey, SignerInfoConfig{})
			if err == nil {
				t.Fatal("Expected SignWithoutAttr to reject SLH-DSA key, but it succeeded")
			}

			expectedError := "pkcs7: SLH-DSA does not support SignWithoutAttr mode"
			// Check that error starts with expected prefix (may have additional text)
			if len(err.Error()) < len(expectedError) || err.Error()[:len(expectedError)] != expectedError {
				t.Errorf("Expected error message to start with %q, got %q", expectedError, err.Error())
			}
		})
	}
}

// TestSignSLHDSAWithExtraAttributes tests signing with extra signed attributes
func TestSignSLHDSAWithExtraAttributes(t *testing.T) {
	content := []byte("Hello World")

	// Create SLH-DSA certificate
	signerCert, err := createSLHDSATestCertificate(smx509.SLHDSASHA2128s, nil, false)
	if err != nil {
		t.Fatalf("Failed to create SLH-DSA certificate: %s", err)
	}

	// Create signed data
	toBeSigned, err := NewSignedData(content)
	if err != nil {
		t.Fatalf("Failed to create signed data: %s", err)
	}

	// Add custom attribute
	customOID := asn1.ObjectIdentifier{1, 2, 3, 4, 5}
	customValue := "custom-value"

	// Add signer with extra attributes
	if err := toBeSigned.AddSigner(signerCert.Certificate, *signerCert.PrivateKey, SignerInfoConfig{
		ExtraSignedAttributes: []Attribute{
			{Type: customOID, Value: customValue},
		},
	}); err != nil {
		t.Fatalf("Failed to add signer: %s", err)
	}

	// Finish and get signature
	signed, err := toBeSigned.Finish()
	if err != nil {
		t.Fatalf("Failed to finish signed data: %s", err)
	}

	// Parse and verify
	p7, err := Parse(signed)
	if err != nil {
		t.Fatalf("Failed to parse signed data: %s", err)
	}

	if err := p7.Verify(); err != nil {
		t.Errorf("Failed to verify signature with extra attributes: %s", err)
	}

	// Verify custom attribute is present
	found := false
	for _, attr := range p7.Signers[0].AuthenticatedAttributes {
		if attr.Type.Equal(customOID) {
			found = true
			break
		}
	}
	if !found {
		t.Error("Custom attribute not found in authenticated attributes")
	}
}

// TestSLHDSAMixedAlgorithms tests signing with multiple signers using different algorithms
func TestSLHDSAMixedAlgorithms(t *testing.T) {
	content := []byte("Hello World")

	// Create certificates for different algorithms
	slhdsaCert, err := createSLHDSATestCertificate(smx509.SLHDSASHA2128s, nil, false)
	if err != nil {
		t.Fatalf("Failed to create SLH-DSA certificate: %s", err)
	}

	rsaCert, err := createTestCertificate(x509.SHA256WithRSA, false)
	if err != nil {
		t.Fatalf("Failed to create RSA certificate: %s", err)
	}

	// Create signed data
	toBeSigned, err := NewSignedData(content)
	if err != nil {
		t.Fatalf("Failed to create signed data: %s", err)
	}

	// Add SLH-DSA signer
	if err := toBeSigned.AddSigner(slhdsaCert.Certificate, *slhdsaCert.PrivateKey, SignerInfoConfig{}); err != nil {
		t.Fatalf("Failed to add SLH-DSA signer: %s", err)
	}

	// Add RSA signer
	if err := toBeSigned.AddSigner(rsaCert.Certificate, *rsaCert.PrivateKey, SignerInfoConfig{}); err != nil {
		t.Fatalf("Failed to add RSA signer: %s", err)
	}

	// Finish and get signature
	signed, err := toBeSigned.Finish()
	if err != nil {
		t.Fatalf("Failed to finish signed data: %s", err)
	}

	// Parse and verify
	p7, err := Parse(signed)
	if err != nil {
		t.Fatalf("Failed to parse signed data: %s", err)
	}

	// Verify we have two signers
	if len(p7.Signers) != 2 {
		t.Fatalf("Expected 2 signers, got %d", len(p7.Signers))
	}

	// Verify signature
	if err := p7.Verify(); err != nil {
		t.Errorf("Failed to verify mixed algorithm signatures: %s", err)
	}
}

// TestSLHDSAGetSignatureAlgorithm tests the getSignatureAlgorithm function for SLH-DSA
func TestSLHDSAGetSignatureAlgorithm(t *testing.T) {
	tests := []struct {
		name                string
		digestEncryptionOID asn1.ObjectIdentifier
		expectedSigAlg      x509.SignatureAlgorithm
	}{
		{
			name:                "SLH-DSA-SHA2-128s",
			digestEncryptionOID: OIDSignatureSLHDSASHA2128s,
			expectedSigAlg:      x509.SignatureAlgorithm(smx509.SLHDSASHA2128s),
		},
		{
			name:                "SLH-DSA-SHA2-128f",
			digestEncryptionOID: OIDSignatureSLHDSASHA2128f,
			expectedSigAlg:      x509.SignatureAlgorithm(smx509.SLHDSASHA2128f),
		},
		{
			name:                "SLH-DSA-SHA2-192s",
			digestEncryptionOID: OIDSignatureSLHDSASHA2192s,
			expectedSigAlg:      x509.SignatureAlgorithm(smx509.SLHDSASHA2192s),
		},
		{
			name:                "SLH-DSA-SHA2-192f",
			digestEncryptionOID: OIDSignatureSLHDSASHA2192f,
			expectedSigAlg:      x509.SignatureAlgorithm(smx509.SLHDSASHA2192f),
		},
		{
			name:                "SLH-DSA-SHA2-256s",
			digestEncryptionOID: OIDSignatureSLHDSASHA2256s,
			expectedSigAlg:      x509.SignatureAlgorithm(smx509.SLHDSASHA2256s),
		},
		{
			name:                "SLH-DSA-SHA2-256f",
			digestEncryptionOID: OIDSignatureSLHDSASHA2256f,
			expectedSigAlg:      x509.SignatureAlgorithm(smx509.SLHDSASHA2256f),
		},
		{
			name:                "SLH-DSA-SHAKE-128s",
			digestEncryptionOID: OIDSignatureSLHDSASHAKE128s,
			expectedSigAlg:      x509.SignatureAlgorithm(smx509.SLHDSASHAKE128s),
		},
		{
			name:                "SLH-DSA-SHAKE-128f",
			digestEncryptionOID: OIDSignatureSLHDSASHAKE128f,
			expectedSigAlg:      x509.SignatureAlgorithm(smx509.SLHDSASHAKE128f),
		},
		{
			name:                "SLH-DSA-SHAKE-192s",
			digestEncryptionOID: OIDSignatureSLHDSASHAKE192s,
			expectedSigAlg:      x509.SignatureAlgorithm(smx509.SLHDSASHAKE192s),
		},
		{
			name:                "SLH-DSA-SHAKE-192f",
			digestEncryptionOID: OIDSignatureSLHDSASHAKE192f,
			expectedSigAlg:      x509.SignatureAlgorithm(smx509.SLHDSASHAKE192f),
		},
		{
			name:                "SLH-DSA-SHAKE-256s",
			digestEncryptionOID: OIDSignatureSLHDSASHAKE256s,
			expectedSigAlg:      x509.SignatureAlgorithm(smx509.SLHDSASHAKE256s),
		},
		{
			name:                "SLH-DSA-SHAKE-256f",
			digestEncryptionOID: OIDSignatureSLHDSASHAKE256f,
			expectedSigAlg:      x509.SignatureAlgorithm(smx509.SLHDSASHAKE256f),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sigAlg, err := getSignatureAlgorithm(
				pkix.AlgorithmIdentifier{Algorithm: tt.digestEncryptionOID},
				pkix.AlgorithmIdentifier{Algorithm: tt.digestEncryptionOID},
			)
			if err != nil {
				t.Errorf("getSignatureAlgorithm failed: %s", err)
			}
			if sigAlg != tt.expectedSigAlg {
				t.Errorf("expected %v, got %v", tt.expectedSigAlg, sigAlg)
			}
		})
	}
}

// TestSLHDSADigestAlgorithms tests that appropriate digest algorithms are used
func TestSLHDSADigestAlgorithms(t *testing.T) {
	content := []byte("Hello World")

	testCases := []struct {
		name           string
		sigAlg         smx509.SignatureAlgorithm
		expectedDigest asn1.ObjectIdentifier
	}{
		{"SLH-DSA-SHA2-128s uses SHA-256", smx509.SLHDSASHA2128s, OIDDigestAlgorithmSHA256},
		{"SLH-DSA-SHA2-192s uses SHA-512", smx509.SLHDSASHA2192s, OIDDigestAlgorithmSHA512},
		{"SLH-DSA-SHA2-256s uses SHA-512", smx509.SLHDSASHA2256s, OIDDigestAlgorithmSHA512},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Create SLH-DSA certificate
			signerCert, err := createSLHDSATestCertificate(tc.sigAlg, nil, false)
			if err != nil {
				t.Fatalf("Failed to create certificate: %s", err)
			}

			// Create signed data and set appropriate digest algorithm
			toBeSigned, err := NewSignedData(content)
			if err != nil {
				t.Fatalf("Failed to create signed data: %s", err)
			}

			// Set the digest algorithm explicitly for SLH-DSA
			toBeSigned.SetDigestAlgorithm(tc.expectedDigest)

			// Add signer
			if err := toBeSigned.AddSigner(signerCert.Certificate, *signerCert.PrivateKey, SignerInfoConfig{}); err != nil {
				t.Fatalf("Failed to add signer: %s", err)
			}

			// Finish
			signed, err := toBeSigned.Finish()
			if err != nil {
				t.Fatalf("Failed to finish signed data: %s", err)
			}

			// Parse
			p7, err := Parse(signed)
			if err != nil {
				t.Fatalf("Failed to parse signed data: %s", err)
			}

			// Check digest algorithm
			if len(p7.Signers) != 1 {
				t.Fatalf("Expected 1 signer, got %d", len(p7.Signers))
			}

			digestAlg := p7.Signers[0].DigestAlgorithm.Algorithm
			if !digestAlg.Equal(tc.expectedDigest) {
				t.Errorf("Expected digest algorithm %v, got %v", tc.expectedDigest, digestAlg)
			}

			// Verify signature
			if err := p7.Verify(); err != nil {
				t.Errorf("Failed to verify signature: %s", err)
			}
		})
	}
}

// TestSLHDSASignatureVerificationFailure tests that tampered signatures fail verification
func TestSLHDSASignatureVerificationFailure(t *testing.T) {
	content := []byte("Hello World")

	// Create SLH-DSA certificate
	signerCert, err := createSLHDSATestCertificate(smx509.SLHDSASHA2128s, nil, false)
	if err != nil {
		t.Fatalf("Failed to create certificate: %s", err)
	}

	// Create signed data
	toBeSigned, err := NewSignedData(content)
	if err != nil {
		t.Fatalf("Failed to create signed data: %s", err)
	}

	// Add signer
	if err := toBeSigned.AddSigner(signerCert.Certificate, *signerCert.PrivateKey, SignerInfoConfig{}); err != nil {
		t.Fatalf("Failed to add signer: %s", err)
	}

	// Finish
	signed, err := toBeSigned.Finish()
	if err != nil {
		t.Fatalf("Failed to finish signed data: %s", err)
	}

	// Parse
	p7, err := Parse(signed)
	if err != nil {
		t.Fatalf("Failed to parse signed data: %s", err)
	}

	// Tamper with content
	p7.Content = []byte("Tampered content")

	// Verify should fail
	err = p7.Verify()
	if err == nil {
		t.Error("Expected verification to fail for tampered content, but it succeeded")
	}
}

// BenchmarkSLHDSASign benchmarks SLH-DSA signing operations
func BenchmarkSLHDSASign(b *testing.B) {
	content := []byte("Hello World")

	variants := []struct {
		name   string
		sigAlg smx509.SignatureAlgorithm
	}{
		{"SHA2-128s", smx509.SLHDSASHA2128s},
		{"SHA2-128f", smx509.SLHDSASHA2128f},
		{"SHAKE-128s", smx509.SLHDSASHAKE128s},
	}

	for _, variant := range variants {
		b.Run(variant.name, func(b *testing.B) {
			// Create certificate once
			signerCert, err := createSLHDSATestCertificate(variant.sigAlg, nil, false)
			if err != nil {
				b.Fatalf("Failed to create certificate: %s", err)
			}

			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				toBeSigned, _ := NewSignedData(content)
				_ = toBeSigned.AddSigner(signerCert.Certificate, *signerCert.PrivateKey, SignerInfoConfig{})
				_, _ = toBeSigned.Finish()
			}
		})
	}
}

// BenchmarkSLHDSAVerify benchmarks SLH-DSA verification operations
func BenchmarkSLHDSAVerify(b *testing.B) {
	content := []byte("Hello World")

	variants := []struct {
		name   string
		sigAlg smx509.SignatureAlgorithm
	}{
		{"SHA2-128s", smx509.SLHDSASHA2128s},
		{"SHA2-128f", smx509.SLHDSASHA2128f},
	}

	for _, variant := range variants {
		b.Run(variant.name, func(b *testing.B) {
			// Create signed data once
			signerCert, err := createSLHDSATestCertificate(variant.sigAlg, nil, false)
			if err != nil {
				b.Fatalf("Failed to create certificate: %s", err)
			}

			toBeSigned, _ := NewSignedData(content)
			_ = toBeSigned.AddSigner(signerCert.Certificate, *signerCert.PrivateKey, SignerInfoConfig{})
			signed, _ := toBeSigned.Finish()

			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				p7, _ := Parse(signed)
				_ = p7.Verify()
			}
		})
	}
}
