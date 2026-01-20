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

	"github.com/emmansun/gmsm/slhdsa"
)

// TestRFC9909_SLHDSA_SHA2_128s_Certificate tests RFC 9909 style self-signed SLH-DSA-SHA2-128s certificate
func TestRFC9909_SLHDSA_SHA2_128s_Certificate(t *testing.T) {
	// Generate SLH-DSA-SHA2-128s key pair
	priv, err := slhdsa.GenerateKey(rand.Reader, &slhdsa.SLHDSA128SmallSHA2)
	if err != nil {
		t.Fatalf("Failed to generate SLH-DSA-SHA2-128s key pair: %v", err)
	}
	pub := priv.Public()

	// Create a self-signed certificate template
	serialNumber, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	template := &Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{"IETF"},
			CommonName:   "Test SLH-DSA-SHA2-128s Root CA",
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

	// Verify the signature algorithm is SLH-DSA-SHA2-128s as per RFC 9909
	if cert.SignatureAlgorithm != SLHDSASHA2128s {
		t.Errorf("Expected signature algorithm SLHDSASHA2128s (OID 2.16.840.1.101.3.4.3.20), got %v", cert.SignatureAlgorithm)
	}

	// Verify the public key algorithm
	if cert.PublicKeyAlgorithm != PKSLHDSASHA2128s {
		t.Errorf("Expected public key algorithm PKSLHDSASHA2128s (OID 2.16.840.1.101.3.4.3.20), got %v", cert.PublicKeyAlgorithm)
	}

	// Verify the certificate is self-signed
	if cert.Issuer.String() != cert.Subject.String() {
		t.Errorf("Certificate is not self-signed: Issuer=%v, Subject=%v", cert.Issuer, cert.Subject)
	}

	// Verify the self-signed certificate signature
	if err := cert.CheckSignatureFrom(cert); err != nil {
		t.Errorf("Failed to verify self-signed certificate signature: %v", err)
	}

	// Verify key usage
	if cert.KeyUsage&KeyUsageDigitalSignature == 0 {
		t.Error("Expected KeyUsageDigitalSignature to be set")
	}
	if cert.KeyUsage&KeyUsageCertSign == 0 {
		t.Error("Expected KeyUsageCertSign to be set")
	}
	if cert.KeyUsage&KeyUsageCRLSign == 0 {
		t.Error("Expected KeyUsageCRLSign to be set")
	}

	// Verify this is a CA certificate
	if !cert.IsCA {
		t.Error("Expected certificate to be a CA certificate")
	}

	// Verify the subject organization is IETF
	if len(cert.Subject.Organization) == 0 || cert.Subject.Organization[0] != "IETF" {
		t.Errorf("Expected organization to be IETF, got %v", cert.Subject.Organization)
	}

	t.Log("RFC 9909 style SLH-DSA-SHA2-128s self-signed certificate successfully created and verified")
	t.Logf("Certificate uses OID 2.16.840.1.101.3.4.3.20 for SLH-DSA-SHA2-128s as specified in RFC 9909")
}

// TestRFC9909_SLHDSA_SHAKE_256f_Certificate tests RFC 9909 style self-signed SLH-DSA-SHAKE-256f certificate
func TestRFC9909_SLHDSA_SHAKE_256f_Certificate(t *testing.T) {
	// Generate SLH-DSA-SHAKE-256f key pair
	priv, err := slhdsa.GenerateKey(rand.Reader, &slhdsa.SLHDSA256FastSHAKE)
	if err != nil {
		t.Fatalf("Failed to generate SLH-DSA-SHAKE-256f key pair: %v", err)
	}
	pub := priv.Public()

	serialNumber, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	template := &Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{"IETF"},
			CommonName:   "Test SLH-DSA-SHAKE-256f Root CA",
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

	if cert.SignatureAlgorithm != SLHDSASHAKE256f {
		t.Errorf("Expected signature algorithm SLHDSASHAKE256f (OID 2.16.840.1.101.3.4.3.31), got %v", cert.SignatureAlgorithm)
	}

	if cert.PublicKeyAlgorithm != PKSLHDSASHAKE256f {
		t.Errorf("Expected public key algorithm PKSLHDSASHAKE256f, got %v", cert.PublicKeyAlgorithm)
	}

	if err := cert.CheckSignatureFrom(cert); err != nil {
		t.Errorf("Failed to verify self-signed certificate signature: %v", err)
	}

	t.Log("RFC 9909 style SLH-DSA-SHAKE-256f self-signed certificate successfully created and verified")
	t.Logf("Certificate uses OID 2.16.840.1.101.3.4.3.31 for SLH-DSA-SHAKE-256f as specified in RFC 9909")
}

// TestSLHDSA_PKCS8_RoundTrip tests SLH-DSA private key PKCS8 marshaling and unmarshaling
func TestSLHDSA_PKCS8_RoundTrip(t *testing.T) {
	// Test all 12 SLH-DSA variants
	testCases := []struct {
		name       string
		genKeyFunc func() (*slhdsa.PrivateKey, error)
	}{
		{"SLH-DSA-SHA2-128s", func() (*slhdsa.PrivateKey, error) { return slhdsa.GenerateKey(rand.Reader, &slhdsa.SLHDSA128SmallSHA2) }},
		{"SLH-DSA-SHA2-128f", func() (*slhdsa.PrivateKey, error) { return slhdsa.GenerateKey(rand.Reader, &slhdsa.SLHDSA128FastSHA2) }},
		{"SLH-DSA-SHA2-192s", func() (*slhdsa.PrivateKey, error) { return slhdsa.GenerateKey(rand.Reader, &slhdsa.SLHDSA192SmallSHA2) }},
		{"SLH-DSA-SHA2-192f", func() (*slhdsa.PrivateKey, error) { return slhdsa.GenerateKey(rand.Reader, &slhdsa.SLHDSA192FastSHA2) }},
		{"SLH-DSA-SHA2-256s", func() (*slhdsa.PrivateKey, error) { return slhdsa.GenerateKey(rand.Reader, &slhdsa.SLHDSA256SmallSHA2) }},
		{"SLH-DSA-SHA2-256f", func() (*slhdsa.PrivateKey, error) { return slhdsa.GenerateKey(rand.Reader, &slhdsa.SLHDSA256FastSHA2) }},
		{"SLH-DSA-SHAKE-128s", func() (*slhdsa.PrivateKey, error) {
			return slhdsa.GenerateKey(rand.Reader, &slhdsa.SLHDSA128SmallSHAKE)
		}},
		{"SLH-DSA-SHAKE-128f", func() (*slhdsa.PrivateKey, error) { return slhdsa.GenerateKey(rand.Reader, &slhdsa.SLHDSA128FastSHAKE) }},
		{"SLH-DSA-SHAKE-192s", func() (*slhdsa.PrivateKey, error) {
			return slhdsa.GenerateKey(rand.Reader, &slhdsa.SLHDSA192SmallSHAKE)
		}},
		{"SLH-DSA-SHAKE-192f", func() (*slhdsa.PrivateKey, error) { return slhdsa.GenerateKey(rand.Reader, &slhdsa.SLHDSA192FastSHAKE) }},
		{"SLH-DSA-SHAKE-256s", func() (*slhdsa.PrivateKey, error) {
			return slhdsa.GenerateKey(rand.Reader, &slhdsa.SLHDSA256SmallSHAKE)
		}},
		{"SLH-DSA-SHAKE-256f", func() (*slhdsa.PrivateKey, error) { return slhdsa.GenerateKey(rand.Reader, &slhdsa.SLHDSA256FastSHAKE) }},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Generate key pair
			priv, err := tc.genKeyFunc()
			if err != nil {
				t.Fatalf("Failed to generate %s key pair: %v", tc.name, err)
			}

			// Marshal to PKCS8
			privDER, err := MarshalPKCS8PrivateKey(priv)
			if err != nil {
				t.Fatalf("Failed to marshal %s private key: %v", tc.name, err)
			}

			// Parse from PKCS8
			parsedKey, err := ParsePKCS8PrivateKey(privDER)
			if err != nil {
				t.Fatalf("Failed to parse %s private key: %v", tc.name, err)
			}

			// Type assertion
			parsedPriv, ok := parsedKey.(*slhdsa.PrivateKey)
			if !ok {
				t.Fatalf("Parsed key is not *slhdsa.PrivateKey, got %T", parsedKey)
			}

			// Verify parameter set matches
			if parsedPriv.ParameterSet() != priv.ParameterSet() {
				t.Errorf("Parameter set mismatch: expected %s, got %s", priv.ParameterSet(), parsedPriv.ParameterSet())
			}

			// Verify keys are equal
			if !parsedPriv.Equal(priv) {
				t.Error("Parsed private key does not equal original")
			}

			t.Logf("%s PKCS8 round-trip successful", tc.name)
		})
	}
}

// TestSLHDSA_PublicKey_Marshaling tests SLH-DSA public key marshaling and unmarshaling
func TestSLHDSA_PublicKey_Marshaling(t *testing.T) {
	testCases := []struct {
		name       string
		genKeyFunc func() (*slhdsa.PrivateKey, error)
	}{
		{"SLH-DSA-SHA2-128s", func() (*slhdsa.PrivateKey, error) { return slhdsa.GenerateKey(rand.Reader, &slhdsa.SLHDSA128SmallSHA2) }},
		{"SLH-DSA-SHAKE-256f", func() (*slhdsa.PrivateKey, error) { return slhdsa.GenerateKey(rand.Reader, &slhdsa.SLHDSA256FastSHAKE) }},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Generate key pair
			priv, err := tc.genKeyFunc()
			if err != nil {
				t.Fatalf("Failed to generate %s key pair: %v", tc.name, err)
			}
			pub := priv.Public().(*slhdsa.PublicKey)

			// Marshal public key
			pubDER, err := MarshalPKIXPublicKey(pub)
			if err != nil {
				t.Fatalf("Failed to marshal %s public key: %v", tc.name, err)
			}

			// Parse public key
			parsedKey, err := ParsePKIXPublicKey(pubDER)
			if err != nil {
				t.Fatalf("Failed to parse %s public key: %v", tc.name, err)
			}

			// Type assertion
			parsedPub, ok := parsedKey.(*slhdsa.PublicKey)
			if !ok {
				t.Fatalf("Parsed key is not *slhdsa.PublicKey, got %T", parsedKey)
			}

			// Verify parameter set matches
			if parsedPub.ParameterSet() != pub.ParameterSet() {
				t.Errorf("Parameter set mismatch: expected %s, got %s", pub.ParameterSet(), parsedPub.ParameterSet())
			}

			// Verify keys are equal
			if !parsedPub.Equal(pub) {
				t.Error("Parsed public key does not equal original")
			}

			t.Logf("%s public key marshaling round-trip successful", tc.name)
		})
	}
}

// TestSLHDSA_Certificate_Chain tests creating and verifying a certificate chain with SLH-DSA
func TestSLHDSA_Certificate_Chain(t *testing.T) {
	// Generate root CA key pair (SLH-DSA-SHA2-192s)
	rootPriv, err := slhdsa.GenerateKey(rand.Reader, &slhdsa.SLHDSA192SmallSHA2)
	if err != nil {
		t.Fatalf("Failed to generate root CA key pair: %v", err)
	}
	rootPub := rootPriv.Public()

	// Create root CA certificate
	rootSerialNumber, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	rootTemplate := &Certificate{
		SerialNumber: rootSerialNumber,
		Subject: pkix.Name{
			Organization: []string{"Test Organization"},
			CommonName:   "Test SLH-DSA Root CA",
		},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              KeyUsageDigitalSignature | KeyUsageCertSign | KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            1,
	}

	rootCertDER, err := CreateCertificate(rand.Reader, rootTemplate, rootTemplate, rootPub, rootPriv)
	if err != nil {
		t.Fatalf("Failed to create root certificate: %v", err)
	}

	rootCert, err := ParseCertificate(rootCertDER)
	if err != nil {
		t.Fatalf("Failed to parse root certificate: %v", err)
	}

	// Generate intermediate CA key pair (SLH-DSA-SHA2-192s)
	intermediatePriv, err := slhdsa.GenerateKey(rand.Reader, &slhdsa.SLHDSA192SmallSHA2)
	if err != nil {
		t.Fatalf("Failed to generate intermediate CA key pair: %v", err)
	}
	intermediatePub := intermediatePriv.Public()

	// Create intermediate CA certificate signed by root
	intermediateSerialNumber, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	intermediateTemplate := &Certificate{
		SerialNumber: intermediateSerialNumber,
		Subject: pkix.Name{
			Organization: []string{"Test Organization"},
			CommonName:   "Test SLH-DSA Intermediate CA",
		},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(180 * 24 * time.Hour),
		KeyUsage:              KeyUsageDigitalSignature | KeyUsageCertSign | KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            0,
		MaxPathLenZero:        true,
	}

	intermediateCertDER, err := CreateCertificate(rand.Reader, intermediateTemplate, rootTemplate, intermediatePub, rootPriv)
	if err != nil {
		t.Fatalf("Failed to create intermediate certificate: %v", err)
	}

	intermediateCert, err := ParseCertificate(intermediateCertDER)
	if err != nil {
		t.Fatalf("Failed to parse intermediate certificate: %v", err)
	}

	// Verify intermediate certificate signature using root certificate
	if err := intermediateCert.CheckSignatureFrom(rootCert); err != nil {
		t.Errorf("Failed to verify intermediate certificate signature: %v", err)
	}

	// Generate end entity key pair (SLH-DSA-SHA2-192s)
	endEntityPriv, err := slhdsa.GenerateKey(rand.Reader, &slhdsa.SLHDSA192SmallSHA2)
	if err != nil {
		t.Fatalf("Failed to generate end entity key pair: %v", err)
	}
	endEntityPub := endEntityPriv.Public()

	// Create end entity certificate signed by intermediate
	endEntitySerialNumber, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	endEntityTemplate := &Certificate{
		SerialNumber: endEntitySerialNumber,
		Subject: pkix.Name{
			Organization: []string{"Test Organization"},
			CommonName:   "Test SLH-DSA End Entity",
		},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(90 * 24 * time.Hour),
		KeyUsage:              KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  false,
	}

	endEntityCertDER, err := CreateCertificate(rand.Reader, endEntityTemplate, intermediateTemplate, endEntityPub, intermediatePriv)
	if err != nil {
		t.Fatalf("Failed to create end entity certificate: %v", err)
	}

	endEntityCert, err := ParseCertificate(endEntityCertDER)
	if err != nil {
		t.Fatalf("Failed to parse end entity certificate: %v", err)
	}

	// Verify end entity certificate signature using intermediate certificate
	if err := endEntityCert.CheckSignatureFrom(intermediateCert); err != nil {
		t.Errorf("Failed to verify end entity certificate signature: %v", err)
	}

	t.Log("SLH-DSA certificate chain successfully created and verified")
	t.Logf("Root CA: %s", rootCert.Subject.CommonName)
	t.Logf("Intermediate CA: %s", intermediateCert.Subject.CommonName)
	t.Logf("End Entity: %s", endEntityCert.Subject.CommonName)
}

// TestRFC9909_ParseSampleCertificate tests parsing the sample SLH-DSA-SHA2-128s certificate from RFC 9909
func TestRFC9909_ParseSampleCertificate(t *testing.T) {
	// Decode PEM certificate
	block, _ := pem.Decode([]byte(pemSLHDSASHA2128sCert))
	if block == nil {
		t.Fatal("Failed to decode PEM certificate")
	}
	if block.Type != "CERTIFICATE" {
		t.Fatalf("Expected CERTIFICATE block, got %s", block.Type)
	}

	// Parse certificate
	cert, err := ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("Failed to parse certificate: %v", err)
	}

	// Verify signature algorithm
	if cert.SignatureAlgorithm != SLHDSASHA2128s {
		t.Errorf("Expected signature algorithm SLHDSASHA2128s, got %v", cert.SignatureAlgorithm)
	}

	// Verify public key algorithm
	if cert.PublicKeyAlgorithm != PKSLHDSASHA2128s {
		t.Errorf("Expected public key algorithm PKSLHDSASHA2128s, got %v", cert.PublicKeyAlgorithm)
	}

	// Verify public key type
	pubKey, ok := cert.PublicKey.(*slhdsa.PublicKey)
	if !ok {
		t.Fatalf("Public key is not *slhdsa.PublicKey, got %T", cert.PublicKey)
	}

	// Verify parameter set
	if pubKey.ParameterSet() != "SLH-DSA-SHA2-128s" {
		t.Errorf("Expected parameter set SLH-DSA-SHA2-128s, got %s", pubKey.ParameterSet())
	}

	// Verify subject
	if len(cert.Subject.Organization) == 0 || cert.Subject.Organization[0] != "Bogus SLH-DSA-SHA2-128s CA" {
		t.Errorf("Expected organization 'Bogus SLH-DSA-SHA2-128s CA', got %v", cert.Subject.Organization)
	}
	if len(cert.Subject.Locality) == 0 || cert.Subject.Locality[0] != "Paris" {
		t.Errorf("Expected locality 'Paris', got %v", cert.Subject.Locality)
	}
	if len(cert.Subject.Country) == 0 || cert.Subject.Country[0] != "FR" {
		t.Errorf("Expected country 'FR', got %v", cert.Subject.Country)
	}

	// Verify issuer (self-signed)
	if cert.Issuer.String() != cert.Subject.String() {
		t.Error("Certificate is not self-signed")
	}

	// Verify CA status
	if !cert.IsCA {
		t.Error("Expected certificate to be a CA")
	}

	// Verify key usage - the sample certificate has CertSign and CRLSign, but not DigitalSignature as a separate bit
	if cert.KeyUsage&KeyUsageCertSign == 0 {
		t.Error("Expected KeyUsageCertSign to be set")
	}

	// Verify self-signature
	if err := cert.CheckSignatureFrom(cert); err != nil {
		t.Errorf("Failed to verify self-signed certificate signature: %v", err)
	}

	t.Log("Successfully parsed and verified RFC 9909 sample SLH-DSA-SHA2-128s certificate")
	t.Logf("Subject: %s", cert.Subject.String())
	t.Logf("Valid from: %s to %s", cert.NotBefore, cert.NotAfter)
	t.Logf("Public key parameter set: %s", pubKey.ParameterSet())
}

var pemSLHDSASHA2128sCert = `
-----BEGIN CERTIFICATE-----
MIIgLTCCAWegAwIBAgIUQ4VjomkBmSw5z7xAVxtfo8zHiEUwCwYJYIZIAWUDBAMU
MEIxCzAJBgNVBAYTAkZSMQ4wDAYDVQQHDAVQYXJpczEjMCEGA1UECgwaQm9ndXMg
U0xILURTQS1TSEEyLTEyOHMgQ0EwHhcNMjQxMDE2MTM0MjEyWhcNMzQxMDE0MTM0
MjEyWjBCMQswCQYDVQQGEwJGUjEOMAwGA1UEBwwFUGFyaXMxIzAhBgNVBAoMGkJv
Z3VzIFNMSC1EU0EtU0hBMi0xMjhzIENBMDAwCwYJYIZIAWUDBAMUAyEAK4EJ7Hd8
qk4fAkzPz5SX2ZGAUJKA9CVq8rB6+AKJtJSjYzBhMB0GA1UdDgQWBBTNWTaq/sQR
x6RyaT8L6LOLIXsZ7TAfBgNVHSMEGDAWgBTNWTaq/sQRx6RyaT8L6LOLIXsZ7TAP
BgNVHRMBAf8EBTADAQH/MA4GA1UdDwEB/wQEAwIBBjALBglghkgBZQMEAxQDgh6x
AKqgUd6wwxTQzfsSRqIxIMntqz/cV6X7RfbwO3/jWoy1hx4fCxWfqlZoQ37qIwUh
0TPLhGFVfjl0GDzqjgGkjZr7NXRpyWI1fw40ARyQQZcT/8WkZa4Pv5sy0iosl4Yt
Seu6rppw5zVnPwp+Ot0LZk74RbLm2HCr+3Jg64WuYjykvzx65d1KJOJO0LU7w6zp
JvhsyjvhRhV/GMVBQJBzuRljhiM6sn8SOl+7wxBsTrJi7jtLxeJpJHQ+boHiaEjI
JyW8sqzaqK51WlwJIhy+lQoLXgwISUI6DS37iTuzFd7u57JeH6bwSvZlwV1eBXpt
KufCwyA3zqsPbOrJOfMo0XWBMX8B4gnIVoFQz076ghpgPoe/YcqgQCeVv/hPBLH9
H3/OKfoVXO+UmvbwDH8Jf+y2NiaDaaotaZ4XehWqm1FDwZB8yWk6WrHud8ko5yHY
kwqAGZxet2FfFGyaACKqTbiGA7WDSunzWnbMozvkE5T3VpZWM90Z2T2NVauZ5QAk
9//07ghHjUOz9OM61RLvBACZYqFezV+fkPPCjjWbikbsVE4TIFlfY9lhseLENtLl
J1YfU1mcJOxqeSsdavKTONjres3XisiY1Idhv3k8KmRCD1sVtL3Ax8TeIEy72A9h
Lqpn4af/DbfdBc9cywxGJuDZSMtFdieIUUnfTBZljBqEggnz1O7EKhepe8B3JP1P
AJgS7RDnZ8N9VHgPyGd/9PKAKxs0DPpfxBKFHF/mhI3OEueu9e/rll9ib4c6NWfK
2K21VQsNBpHTnRqWLmfYsQ6PBz971v61dmIZg/bSCDU7nx0K9xTSRVBwXJHMtQ9L
73nv08e9Anr6i4PNMQew94p5xGgZ3gH4cxptisdUyEuaQFPjS+S9OlJQxt7eGdee
qIhw8XCmEVWwRl5AN7KQXJF2vSAdJNtxM4G4R+/sfnjSJStL4m4BgdQS/0D/4NeQ
KYWA5kr1WzJstwUcICfgmFeA56KXy5HO2cGjX9wkf7j1XNqRg+WujGVzhGpbyT+X
UX3MP9Y54XHxVI0fTzNwzAf4A3C+jIHhXXPBnL58PWnAzHKQz2U4NXEWrh3ipgjI
e93AMPS0KkX8BeYc76/zUwMvdrV78al9FjOxtcJPm1V7DSL2CEs4smdO2fjxZQPW
Wh8fi8vaePx7UqXXGzWyzQZ+Hh2LYECRdC+RycbHxAH1LxDC6quE9vYu/HfBhSiQ
pRHc7Qd4wnScYIZpQDwXmzrl6GUiwn/ZiL5DajGQ1SM365Nw5Lw0lE+vpMFv8zAb
xuH18dh7pE5uab6C0ICorplE4db6ReUFpVIKXWAXOh4u3S60hpMxkw/KXwVSjjEV
6IswiDPX2pFSQDzXGLxyjYiyZcX+CnxQRH4PtlJTiyj8W/qTVDbK4cFrf0YT3gV9
vjONZ1K6ba9L7gELx1YhfRa9GYOQyBRRi/uDwaXKaVqu2fGn3PdTn/ajQ5T7OIYf
Kg9Qz428NlHOjq+A/rWA+ENz6jrXoqS2czpaa0inMaPTQjr8LrAp0meKmtEmlQgL
YT9x7rGW9EkM1ztQYWwVyjEx3A382F+hJtPiQ80TOUpQLWRXvwKoXFRK1DdF8gn9
z1NnGemSpM0bggksTSkwgMEji8ocOMYRj6I8LH+GJcn+oxr8gqtp6bU3sQ6amRDN
p7ZSn8bkbgjxkM0UuMLgqVguikxS39XuilfOglemiQ90IEwiHQLJBFJoePNZycNg
hZIBMHWg6ykrZlW3SErfj7rfqLzZRVzrBKjDlLa7HQUZSJuujWMtutbTXuV6QLYF
dKGwerfXtGfW1qz1BW9TRabt4AyzDDLGiftCexF0lCXcAXy7Tk9Pl1QosPtIZoc6
0NoYv6oTDGrTxz4RJkPoQLNXKQBwAK9YsHWDnrlLWznxfz+JjR0LGnhN5YzmB4Z1
IxsUH80ETZjRzfVPHQBV+/jHkvXuXsXzJIQi7hFIkUtR94eonKCaSLyT9Twcftms
FRwft/m5Zp/05VhK+X5cP6NaIFS+V3R0ZYAN9DCpDVPmcVL5fvQCJOW0IQu8Ey5n
AL1kVIuCtGT4Ukay8jddMkmKvhlOIafMmhkpyVeq/ttK7+ChBhpfWEyXrv6sFqDj
p2Dvtr+AZzXIbP4RFhi9BJAytnVkE1WyLsbfL7c11jzxq0we2sJP/CTyks5k3e9w
eq4mBwFhn+Yu/uQ1jNXu4r79O4/E3FxQTFouqhTEDrWBE1XQhYEWPc4D8CslObb5
zv/A9U13YIYDJf/dV8v9KP3ijrt8+0lGnCwONHTP0rhFvv3BKmuOMEjDp0FnBHho
nYEcNfSTWh9Hqzo0Xk4tQyv0UrxYNFIVUzYZybC8V3yVs4bufmifc7IJME/4kK4L
jfT00Ucb6NEDhZItimCrMPPqJl436ZC2LfYIH7z9E1r9qSl8q1gQ2W07J3Ux9HSo
6HAAo2PxjLSXIivQ+OCybk9KltXwPf5z4ci6+6iWvwHCY3D63ZflyY8ABF36wDlo
uuXcqns9vSWqQ+ICoVcreHSA+NbqokR/HjVGy30vg9x6JYfgJ87fEhWDtiYq+U4i
GMppfeNohghA+kUbpT1joaoZyoM9LksTTVgmYvLvPGsTzJmVIcLH9a8I76AhGkvp
9BxNRnKIIouqtdz+O+aNuVGNRfRwE2iiKwqcghZk/DpaKhmm/pI0ZeJqnKWTJCG0
tlC4BDECHN9PuJy2OxlmJqrAM/2b+wIvyAeMH2aK9vPFC3TOdcSUNIBgU8FCCS0h
+yW0/8EAMPHIrc5ixh3XlMwPeyoAvrPzyD/liK9tGZAxcZbWjFs0uIW1QvL7F6CD
u2phhvDvH9vOAC+Qqu4Hl1lWhZYcl2vK1H2avdwBUt0cvIJegQiRNoV/PhJjWaoD
ELMDLa0XfWGR1uG5LjlUJ4qkkYe6M1QoUg1G8OdjQG0VdhFRKBtflOowbwA0pthC
xDKgNhtVBJCHji4ER/ElyPvUWHk2XLmBGMX/Fqv+uAEK+0qTPZvFgtUfv5Xqqjbv
xfjYq/fKyEncMPs0nYHifGwGeDSpqkR0n0KlxZGfQcTxeX4NzTbVITJdgk2zgA1y
GasqDt70Is5It7JEAvGZsb953UkLvz74uaXjKI2PibPYvJfLLvjAj/AQzQAv37y7
q+B33tlEF45w8AfhncWl+5HuPe70mJ1nEAQ6pvID/OgFU+4AKTyE/zX035N0ghbs
WCVDgQGyaNKnUe2X7cIGHuuNdc8RMLD3D8HSwfFDXUJw+sH5KuuirwAHy5nKy5pQ
hcNjdtOt9e/U8Ml1pEuISzKBw0OXv6gLwFojtChGTARwNoju6/UmspkFzGsKDvkG
c/3DvjfHJikRYtQg4AbyaMNX27+F5i/L8YGWiHCeompCAvx5kPbJsPuzbqVoxO67
jIdsgSAVqH8buvcusvdfo8ADRM7iJ/IE0MCyfb6zEU7pd3y+g5QDE3UvxNSK6byj
+m1ccvpihhfi25eIymxMrWgrV8/1tpIuAi6C0VyfO47p5Y12fGWdV+Ur38nKsYzs
hucJld5zV07sr2JHRXnG/Qky2Vtz3mdEOSij/x2PImEESIT78EQEDwEbrb+f/zQs
gz3WhTybgu9Hx6ui4p6scevWXqfY4HlTOSkVDqa5VjmTFn8KSABtNgoqShHvgNdD
xPAG4qJJmuYtxf1GlqiDRSK1x1Xczz+EjgtpfNzgMBofphTWQtMPkUtsPy/5ZCW7
5IO5RICzbMfyPlijYXoaBGHYooznQ9fr9JBIkDDcwVWz60toCa9iedf2CWGJt2s3
PglO1dfjBbFL8OUfaz7wa+sqjR2u9ofGcPJ0+pJGHdZ+1qsa094Rcb7woeMFgk46
oS7SK8SSDqNwED/fxMxSl/dMplp7zOh0WkcSQnPYWwl+MaloM3f20XJyoyLi2W7F
/PIw1YXFwlB5EKafFVAxpIfXy9q5Xzer/n8JJeXDHsDWeCCgISAQbzzQvUb+vK3f
JSeN9A0MTbIwsXCOqiWfgLlgt3myJb6l3+7tjKyHyWk/6uXPTdFEc3+nTptpZN/a
ildTEQ5U/a/KTG3grVYff8UHAIvkswlTr6Tb4aHE4cDWcNQt6NS9OJTHkzlkcVBt
pTB9/h5h0KEmu2r4MmMFN2W7I5cGE8bWRrWD/dObo5TsZ46cu56vC9/oKO1F/6SM
2fnjMN0g8j2tT9C5Kxe/0EqOA42iHxb6/ofrPFd9+Hj5LXTUgthT4JG2g29zecrZ
yoPthHUQ4F76pw+hm2ch0JqwkINoPJmXaUIRLFG5b1wDHy7ueLc6FNvYnRdpmq2e
gNXX3v47GO6mfZ87bzBndKH0//toreTsj39bAkZiJhBqiLGnidGHAKSVhJaetB+/
8W9ntj/VwlwfQRDNBqXo/uIeUuNcRrnE6RiqeOBLeIJ4rD1Z/SRARAHWrWuHvRGh
wb3yqcy+rgVSe72GY9aevVI8Jdyku3O8DAQEwQzpbtEmw1CsmPtLScVp7dgwu3zS
btN2WhMMgijPQFwOFiTogl0q8IeJI5ktfmqFod2reBvmz3a8/iayJqWn4dREo/8g
rYRzWyayOhXJxAKd+7Irz7Xyo36Z3vnZk/eLFuMET8S8TWebP7oteXpH8erYNs9d
6/ezrgzgYvj2LNApkYr6aL8gV+95DXFi96clx3fyA0gtlXN7usD1Ynu7DQa2iHSk
tH5IuaZtkng9h05oRNZFI8l7BAJ+x0B/oEH8JI7lQxn0ZbKl53MnA7RSDt4zEmLt
tsMrGc2gaQvLY+uFg6EWqStywefGY3+kQW4ZYTt4uttqGFz0sV2lXd84/V+Az8/w
leGxvHouLP8EAF7HeRxH4KdX3hvmaRN6O8+g2GkW8p5F5rF9n/dHJdkfUApu3dpT
4E1SkTOHij8373rrGpigVeD55fIDH+Lr5TBsDEt1pM9Ah9owSSXhJf04zkQg43V/
JSt73bIC1+IPlqS7zwzfFudbkUYxvE0YtsozoVvmcJUDQHmpEqkdCeg419R9w6gl
bMKqC3gZWxbLiiRPsnrKh2iFmyIXUOr9KK5F97a6dt5Jzp+kSLG78br4iI4UHi8t
U3m/Mg78GSCxuhJoXYzYPDzWY4oui+R8dQUnqOngW76Hd9WziHTbzV9ZEFycROHU
fb827Ptwlb+nG9mo7v3XkU1ysdFyhwsCWCIjy7FyNgRHM6Y5mTT6c2rhuSEXegRb
I2Rln78U5o1OcBueGa+bmD5vEy41pZCnxiSKttAKoWDrQM97xQOH4qd2ihBbTnXB
Pq03Hv9GWaixbsT+ZYFhZ22DUZ8iWB+i4Tnd1DN0IpDLk79lplqNktuemmAell9d
ZhO484L7E1rqPOkfXde0fxiZONMeSYMmqOzAE5ivos8tKkpKfjL8ILWEwC/WDEBa
rTTb/NXzjF7OzRX7aNRgxA76nPF+C8KVz+Efa0u0i30bBUWOZWLYJE/JMfWeGzrT
zUcFk+CRiZ9+h1CpCkso3wBVAX9Y9tSKF8JgGlYqSZyNESV+QudgkCD3PhIle4IF
SdUviM9z2wl+D/F9xqQP3D1fJaQr4XR9cFqltGdsZnTEhgEwr9Xp+klyODsAld77
xq7uyNCvshSPndoyX57nhXapGnzTaYsCSzz/UTuggGnwlQEQrrqUqVnOoJCvjfXb
RWMLT4r7ltsmZtq44s9+FUfIEANGjDu/Rgwp5n2AQjrCjTi0SC0slqE3cROccgAC
/6R5/3RaMbqmOiQIv45BtEhvvEOFMX25ygZgdvun0aOvrdCnywcCCLq3zqsGVihd
MXks2xBSVUxlUxDOHl8O5RUlxOB4EjzSDInzYN3x74vsfoqbLFibH3vw091H10lf
EfrtenIchGwGD3ZEqOYvJBs/ZkY858Z/4wYbXnzm1mcINPNkLP0wndjidRSVkdAP
TNnwlUNCshXbTz0Vy2BsIvj74MRDHNBxnRCb9nbD1Ojx2GKzs4/04mml/eMKI+ZO
mw+lLKEJAc4nJpSnkMDoDoKYQ0SHnTRXc7W3Nfqjr0fPCUgnedPGGwR6CN+meA9q
LlzlxqYWrE9NbQbWRd5oOizyIjJhjObQ5WKpSf66hq3Lxr4pawtLzUxZTr0XbJvJ
1tnNn6oBjMmj3a9rX+n1GCRtkOEUnlaGBC47okIh+AruBXExVfdWmV9yGIci/21P
fMLCMoRdTB3aWRJxSJg3aMhsFIy2jNRJ5fYrDwSsZhv3xNAYbeNdEk2dNMZMNs+W
K12u17F0yfBEtvDGRTJOt0JC0/m1w1FUPrhKcA6CLjkHvGapkZND8n/tpGHyNfrg
n4YAyYdbaX47+NH653jm0EYn1YDUNA+PvxwnR2A/p7XE7bPCFTc3s4vRwacbRyRz
ziJ02vvIP6FlTXln0YrbcXnUXX2hrgWTeDGY0/bMo0KT4REGUSw8TLdrXQf6qAhy
TJomC68oHHBVsR3Igpg9pbRi/3cHE4SwEH7zMzchQS7NO9pO5vqtP+7zBTmNZSDc
lEmY5OmhJrM6PclpH+ScKX0bkQJwJ4t33xh+UFBYBhv8N2tMAHHq7oJM4oukp4H4
h1cHUNnQv/SFx0+bz+RR7tFrCqOneal/5Grrg1mC+OUyxmuTVxhh54mx/6f3MYtU
Md8wyAsvflxNHZnizWGXtSgUNj82DrQnOMhhaOCVjSY81INdlp+mN5ZZ2xCkX5C2
RPF+bIZEJUAK/O/XXJe6G0yVnuOekLkCWDAdYLeUMPV4taTqN4J69XNsDdOBynLM
jM2/b/p/yzknGlmacVHY87NA09pmg/TylKWPtaB/csLI5xtBNv77bYHYq4ozQRi/
QskaiiL6JZ7gt0VG7qs7VzqPZJZReh9mlflSlUB3UWn1br08l5VTkAmw/F+MytUt
QKspwiExgHW5DMlXRvl+4fyVY8GRrRCQry2ihQJV0aEQdtskrDcdNb+KCSkht9rV
Jm0Abnc/ZOCIawk36YL4x628BeoddaS6w9T7Q66ZKDoZ/YRTS4SKs3aupt2pu/5W
wn0UBWI6pK99O82AxN2HWFQhniHyYKNCpt5VMY7JfAGu/YdnUkO6eqTuI59vClLb
OBJBGMQtSoWENlmmI544jlHCiCOFOtxgUlZ5mYSwpamzG6wnyF1Ngo087ueExw1y
rIDIglW7BXseM/SjDDlbK+2k9s+lFY9YvqC7mzUnzHt4qu6rD/reqruVlDe2RP8h
4WRBc0Yi2bCJYSS0UwGZF0t56d3gPQrJPdUCHElOvSbZm7AyLmoiuHD1xu1RT+6g
Nyl18xddNdKmO3FDi28imxp9oMX3f34kepNnuQtMhGHy3W1vYHtjVkfGzRyuJRip
zyGqvNVwSHU4pxBevLyh4CdPbBi0QPiAAXQf/NKCWLPE8xzx5WZhwGxjTDu2YXoV
nb51S8MENaOnA/nMUGLQOHTB4sjORht2QqA7/1w8BMdzPas2tBzvR36ZeQyHnVTJ
RUphKUM0ck6m2SQsMHR1PRaHkQNYPnk789GLahCHGJLJDeWqY0UKYIPCgRE4tsPN
+LBx2OBbBMVXKlU82z+CJuvbCbcL8miQNL55QSWXndGXDq9MrkAhYV7zvpnao4Ix
mJZbHIYgSGuvkt/nLfUNl1UESz1vEEeYafMGi6CaiHwKooSNcUpfI3Qu7bsoMtIz
NKt3QOf41Bb+sHPkFKX1PD6g8OBCHc/Dw/i7B1pWIG1Pjqxj9jz99hErlyyGZmYR
FutRwikGMIS65IGYVmhwQzFdwu/r5uWGy5vjN46j+q1GzWOd0qFtXd9lz3w5zSSu
hkCwP9N3HVhUShG5fSXAiHnXNseqLNg/24aC//kPItBacYxbsiPqysvutlEtXkPa
/RiERyKVMeDlaC1law/5lEDoRU0W0GusVyTe4sHrmWWRnnpsbG7HN6suToCACWDV
EAtRmyR/ILJ9d7XhM6IuwHpi+6q8qLoH7yfEacBL2v+JgBOCHyVZO0DcEfRd3sWk
oNVHwBntHtNnSrB224Ut30/rbhesnsxnDXQDEFuI097H4AVVSAG8vnqCLPtePffK
LEIg7VD/PCsHxI3RE1eqJmeDAht5iATF7wpuyPikzZNXu0o5S57BF2dUn4Vei6QV
84G6LYVkqJnqEQybg1KAAxjAHXKe0gvUjOVZCCilz4tG7+mCm1Tw4glwtC30MdHx
6tpXHBu73rOFR/QZ5MQGhYdUI3Zs4T0owcAlALM001Gv2d8Pi7i1bchT/o1ZuvEO
AAVOv1GbWRBZBw9fJ5mffGujFEAy2uSJjbXG0z/t4/ktFazRqBFBLSxyq6TV9Jyu
1699OeIcj6j/PpJ95HY41P6imW4daxFw497yTR9N5cxEQ/hCyJkRxiki7vkT1QgV
cfwOyoKXsRH7uYwnPL6k19hPPA08gl3PGAEJKMod8Pe6cYDrdnpY6ZG4hnHQcdIT
PLdl58T/J/cv8j8k1cbfbNDdCu7eSxZmb2jOlLH5aWcMxBkgLCl0+KfiAAYTyS0d
T3Z0AyhGebeAstrSOQpWR1/DgZruF5ENSfQjPzbbVUjYFkP/bG/6yqwXyqNiTd5g
XO31o5YzNVMkBpmPMNakuAc94dnKB5tUcFDGDtJLk5wHFreeHtdCjMb9Qc2qTvws
ERpuANtbJW6WyClDrGi+wNMsPBvUtpwqoJ+bFqMq3e0ALLmdk1llgd6pqbiWrMRD
MJMhTDxCBo6r+jeWcsjsIhkbi8oic74I32od1+8TC0Ou/aDWoRCK914T5V2hgcCB
Bj9f6rPheJn1LRxWC9/DHU4f9uointgzEyu76T+xF88zDoCFcnJywK1wtIGb2FfW
pJ/3khXjctDuIqFHsJDj8RS2mf/8w8s0A/gAdt19xE0dwutIc01BQJ3hgFw3zGWn
aoqwmjXVLMzzo81D9+dcRnrhX7Kgk9cAyp46FUxhq/xi5Dl51iIq2X6PpGUa6R2J
K5zv1z82/JOc7OWmk87sMpFIRrAKsuMzGd+h+3gg4xNUE/P7ilrynro04f7rWOLE
r7ZjVjJCz+N9xfDVb/ZkU0AXwIjwVI2cBY1SOWNoI4aGkTTynKTdF7omWn9zdxlb
k1osiQdfJ0UrqoYamJhZKkbIjk91MNw66fYfwDPvChMwXDJFiBlnTk2o8fqJsO/k
Qj4mYICTIXtGufRsvp/Gf8ZJyeFJyC0HNpNpFBjj+ztreTcAvfLh9gZ7LAfqhuIe
YmRIQ1l9L/0kyKFPlKyNHn0VoTIBJbo/NdYWVyQo9mg104AhzJF2vRV/oUJrjqWQ
e/pdAXouAiG0MfksQIg0dQHLgzkbPDiiwl0z44NVf/rw18/JZJ8GObIY80GBYP9Q
XVASNw6CwNovavj8Fl+7IimDFEakAcr42Cx57c9AN0aoSH9mfQ6g/y8HwKNY7Cw6
JzPjP1KslJkQKxWEEelxwDXDefclv/NbQkYXRF3BxKz8AWBqaV3MZQjgMcDbAe14
cBgbk6/3sSwLH7Volrj5aZ/l5jXLvAZlZBHVq9Tm03kxobDi04B4wvaHdOM0SKuL
XjBS1jsCcs0+pPnaym3abFkHOXPaCPDQPJ35UoN3YGdYn2cRJBP0hoaNKYnFToYi
EoYRlA70xiY+D44GjVpgMNCpqL92P4g0eajaeBtxn4wzWY37a8+WRU++VOUVxtOb
ferZYVN1kT3FEH2iXQDNSne6lmxRV6RodUMn7AtJSk0lyTj9zDMb2nC/G8PUWd2K
Bf6HxY5ZFu8zS4gU9I4/ZUPr6qOcXOvcgdffe6UeTYRczTHiAqY3z4FPtZFBhwSS
88FdYi5S8YaujRO/tsdWNu/ml7YFzDnbSa+1PuzKNy6kUcbXAy3IaTtY95Ht1IgO
nAV//oxfDBgxOUutPCVNJiRCRZkY3w6sk0cLR2BYU2MPC7BnpQcSyqFk6aO+Ft72
cI4jjWHXjUsxb3lIjLC+AUjyTj0qT+BVkHI+0wxc9/gVReQQ362c0CPDu6NScAji
+q66sHQ13aZL+5q3PCgXhwhwR0JeWDqmhKyUNEFcPNGsCrS/ocbawlmjIsym4+nV
khWAuy4kkdOKAhPlUQX1VUp4QdXnYh231R/lNPexrsYP7DjCqCOO/122h4pPv3fW
wa6hyIjVZuF3BsqRENsUIEygj9iLG3FmuJYJCGrs38FL1pEDjGbiyB3JDvOZPgq0
YIOKvD3KGQCz/bBehGG3IwTbZDUGmqtKA0eieWzYC57Jd7tHXttm5PMz64ziSaTW
oclhl0rmOqsWZLPfFlre5fm6XX3rBPX08PB95Bp0/H0DFqTK9uAFleD6nYAHWLQS
XjRDBK2Qnz++Mco908nQt5HHXNArgXM0v8qlbiNPs/O0vwP0va/91wmLZaMMdtwe
fJfSvoXUZW35PW6ubFf0EEAh1gQtm5vllZCcUqitYYvNsBLBEybDTY4igoKb/m0B
5zxlebR5n56wEN1ealdDjGtB1earlLrHZ6W0QdgQDP0pd+ILzSmALq5epYWjogkx
UYKYCyx6a5bvjcD1H5i09iK2IW4247sY2h0kRg1lKLZq
-----END CERTIFICATE-----
`
