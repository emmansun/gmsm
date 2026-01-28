package pkcs7

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"fmt"
	"math/big"
	"testing"
	"time"

	"github.com/emmansun/gmsm/mldsa"
	"github.com/emmansun/gmsm/smx509"
)

// createMLDSATestCertificate creates a test certificate with ML-DSA signature algorithm
func createMLDSATestCertificate(sigAlg smx509.SignatureAlgorithm, issuer *certKeyPair, isCA bool) (*certKeyPair, error) {
	var priv crypto.PrivateKey
	var err error

	// Generate ML-DSA key pair based on signature algorithm
	switch sigAlg {
	case smx509.MLDSA44:
		priv, err = mldsa.GenerateKey44(rand.Reader)
	case smx509.MLDSA65:
		priv, err = mldsa.GenerateKey65(rand.Reader)
	case smx509.MLDSA87:
		priv, err = mldsa.GenerateKey87(rand.Reader)
	default:
		return createTestCertificateByIssuer("ML-DSA Test", issuer, x509.SignatureAlgorithm(sigAlg), isCA)
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
			CommonName:   "ML-DSA Test Certificate",
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

	// Get public key based on private key type
	var pub crypto.PublicKey
	switch k := priv.(type) {
	case *mldsa.Key44:
		pub = k.Public()
	case *mldsa.Key65:
		pub = k.Public()
	case *mldsa.Key87:
		pub = k.Public()
	default:
		return nil, fmt.Errorf("unsupported ML-DSA key type: %T", priv)
	}

	derCert, err := smx509.CreateCertificate(rand.Reader, &template, (*x509.Certificate)(issuerCert), pub, issuerKey)
	if err != nil {
		return nil, err
	}

	cert, err := smx509.ParseCertificate(derCert)
	if err != nil {
		return nil, err
	}

	return &certKeyPair{
		Certificate: cert,
		PrivateKey:  &priv,
	}, nil
}

// TestSignMLDSA tests signing with all three ML-DSA variants
func TestSignMLDSA(t *testing.T) {
	content := []byte("Hello ML-DSA World")

	sigalgs := []smx509.SignatureAlgorithm{
		smx509.MLDSA44,
		smx509.MLDSA65,
		smx509.MLDSA87,
	}

	for _, sigalg := range sigalgs {
		t.Run(sigalg.String(), func(t *testing.T) {
			// Create root CA
			rootCert, err := createMLDSATestCertificate(sigalg, nil, true)
			if err != nil {
				t.Fatalf("cannot generate root cert: %s", err)
			}

			// Create truststore
			truststore := smx509.NewCertPool()
			truststore.AddCert(rootCert.Certificate)

			// Create intermediate CA
			interCert, err := createMLDSATestCertificate(sigalg, rootCert, true)
			if err != nil {
				t.Fatalf("cannot generate intermediate cert: %s", err)
			}

			var parents []*smx509.Certificate
			parents = append(parents, interCert.Certificate)

			// Create signer certificate
			signerCert, err := createMLDSATestCertificate(sigalg, interCert, false)
			if err != nil {
				t.Fatalf("cannot generate signer cert: %s", err)
			}

			// Test both attached and detached signatures
			for _, testDetach := range []bool{false, true} {
				t.Run(fmt.Sprintf("detached=%v", testDetach), func(t *testing.T) {
					toBeSigned, err := NewSignedData(content)
					if err != nil {
						t.Fatalf("cannot initialize signed data: %s", err)
					}

					// For ML-DSA, use SHA256 as the digest algorithm for hashing content
					// The ML-DSA signature will be determined by the key type
					toBeSigned.SetDigestAlgorithm(OIDDigestAlgorithmSHA256)

					if err := toBeSigned.AddSignerChain(signerCert.Certificate, *signerCert.PrivateKey, parents, SignerInfoConfig{}); err != nil {
						t.Fatalf("cannot add signer: %s", err)
					}

					if testDetach {
						toBeSigned.Detach()
					}

					signed, err := toBeSigned.Finish()
					if err != nil {
						t.Fatalf("cannot finish signing data: %s", err)
					}

					// Parse and verify
					p7, err := Parse(signed)
					if err != nil {
						t.Fatalf("cannot parse signed data: %s", err)
					}

					if testDetach {
						p7.Content = content
					}

					if !bytes.Equal(content, p7.Content) {
						t.Errorf("content mismatch:\n\tExpected: %s\n\tActual: %s", content, p7.Content)
					}

					if err := p7.VerifyWithChain(truststore); err != nil {
						t.Errorf("cannot verify signed data: %s", err)
					}

					// Verify the digest algorithm OID is SHA256
					if !OIDDigestAlgorithmSHA256.Equal(p7.Signers[0].DigestAlgorithm.Algorithm) {
						t.Errorf("expected digest algorithm SHA256 but got %q",
							p7.Signers[0].DigestAlgorithm.Algorithm)
					}

					// Verify the encryption algorithm is the ML-DSA OID
					expectedEncOID, _ := getDigestOIDForSignatureAlgorithm(x509.SignatureAlgorithm(sigalg))
					if !expectedEncOID.Equal(p7.Signers[0].DigestEncryptionAlgorithm.Algorithm) {
						t.Errorf("expected encryption algorithm %q but got %q",
							expectedEncOID, p7.Signers[0].DigestEncryptionAlgorithm.Algorithm)
					}
				})
			}
		})
	}
}

// TestSignMLDSAWithoutAttrRejection tests that SignWithoutAttr rejects ML-DSA keys
func TestSignMLDSAWithoutAttrRejection(t *testing.T) {
	content := []byte("Hello ML-DSA World")

	sigalgs := []smx509.SignatureAlgorithm{
		smx509.MLDSA44,
		smx509.MLDSA65,
		smx509.MLDSA87,
	}

	for _, sigalg := range sigalgs {
		t.Run(sigalg.String(), func(t *testing.T) {
			cert, err := createMLDSATestCertificate(sigalg, nil, false)
			if err != nil {
				t.Fatal(err)
			}

			toBeSigned, err := NewSignedData(content)
			if err != nil {
				t.Fatalf("cannot initialize signed data: %s", err)
			}

			// Use SHA256 as the digest algorithm
			toBeSigned.SetDigestAlgorithm(OIDDigestAlgorithmSHA256)

			// SignWithoutAttr should reject ML-DSA keys
			err = toBeSigned.SignWithoutAttr(cert.Certificate, *cert.PrivateKey, SignerInfoConfig{})
			if err == nil {
				t.Errorf("expected error when using SignWithoutAttr with ML-DSA, got nil")
			}
			if err != nil && err.Error() != "pkcs7: ML-DSA does not support SignWithoutAttr mode, use AddSigner or AddSignerChain instead" {
				t.Errorf("unexpected error message: %s", err)
			}
		})
	}
}

// TestSignMLDSAWithExtraAttributes tests ML-DSA signing with extra signed attributes
func TestSignMLDSAWithExtraAttributes(t *testing.T) {
	content := []byte("Hello ML-DSA with attributes")

	cert, err := createMLDSATestCertificate(smx509.MLDSA65, nil, false)
	if err != nil {
		t.Fatal(err)
	}

	toBeSigned, err := NewSignedData(content)
	if err != nil {
		t.Fatalf("cannot initialize signed data: %s", err)
	}

	// Use SHA256 as the digest algorithm
	toBeSigned.SetDigestAlgorithm(OIDDigestAlgorithmSHA256)

	// Add extra signed attributes
	config := SignerInfoConfig{
		ExtraSignedAttributes: []Attribute{
			{
				Type:  []int{1, 2, 3, 4},
				Value: "test-attribute",
			},
		},
	}

	if err := toBeSigned.AddSigner(cert.Certificate, *cert.PrivateKey, config); err != nil {
		t.Fatalf("cannot add signer: %s", err)
	}

	signed, err := toBeSigned.Finish()
	if err != nil {
		t.Fatalf("cannot finish signing data: %s", err)
	}

	p7, err := Parse(signed)
	if err != nil {
		t.Fatalf("cannot parse signed data: %s", err)
	}

	if err := p7.Verify(); err != nil {
		t.Errorf("cannot verify signed data: %s", err)
	}

	// Verify extra attributes are present
	if len(p7.Signers[0].AuthenticatedAttributes) < 4 { // At least contentType, messageDigest, signingTime, and our custom attribute
		t.Errorf("expected at least 4 authenticated attributes, got %d", len(p7.Signers[0].AuthenticatedAttributes))
	}
}

// TestMLDSAMixedAlgorithms tests multiple signers with different algorithms
func TestMLDSAMixedAlgorithms(t *testing.T) {
	content := []byte("Multiple signers test")

	toBeSigned, err := NewSignedData(content)
	if err != nil {
		t.Fatalf("cannot initialize signed data: %s", err)
	}

	// Add ML-DSA-44 signer
	cert44, err := createMLDSATestCertificate(smx509.MLDSA44, nil, false)
	if err != nil {
		t.Fatal(err)
	}
	toBeSigned.SetDigestAlgorithm(OIDDigestAlgorithmSHA256)
	if err := toBeSigned.AddSigner(cert44.Certificate, *cert44.PrivateKey, SignerInfoConfig{}); err != nil {
		t.Fatalf("cannot add ML-DSA-44 signer: %s", err)
	}

	// Add ML-DSA-87 signer
	cert87, err := createMLDSATestCertificate(smx509.MLDSA87, nil, false)
	if err != nil {
		t.Fatal(err)
	}
	// Both signers can use the same digest algorithm for the content
	if err := toBeSigned.AddSigner(cert87.Certificate, *cert87.PrivateKey, SignerInfoConfig{}); err != nil {
		t.Fatalf("cannot add ML-DSA-87 signer: %s", err)
	}

	signed, err := toBeSigned.Finish()
	if err != nil {
		t.Fatalf("cannot finish signing data: %s", err)
	}

	p7, err := Parse(signed)
	if err != nil {
		t.Fatalf("cannot parse signed data: %s", err)
	}

	if len(p7.Signers) != 2 {
		t.Errorf("expected 2 signers, got %d", len(p7.Signers))
	}

	if err := p7.Verify(); err != nil {
		t.Errorf("cannot verify signed data: %s", err)
	}
}

// TestMLDSAGetSignatureAlgorithm tests the getSignatureAlgorithm function for ML-DSA
func TestMLDSAGetSignatureAlgorithm(t *testing.T) {
	tests := []struct {
		name                string
		digestEncryptionOID []int
		expectedSigAlg      x509.SignatureAlgorithm
	}{
		{
			name:                "ML-DSA-44",
			digestEncryptionOID: []int{2, 16, 840, 1, 101, 3, 4, 3, 17},
			expectedSigAlg:      x509.SignatureAlgorithm(smx509.MLDSA44),
		},
		{
			name:                "ML-DSA-65",
			digestEncryptionOID: []int{2, 16, 840, 1, 101, 3, 4, 3, 18},
			expectedSigAlg:      x509.SignatureAlgorithm(smx509.MLDSA65),
		},
		{
			name:                "ML-DSA-87",
			digestEncryptionOID: []int{2, 16, 840, 1, 101, 3, 4, 3, 19},
			expectedSigAlg:      x509.SignatureAlgorithm(smx509.MLDSA87),
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

// TestMLDSA44RFC9882TestVector tests verification of the ML-DSA-44 example from RFC 9882 Appendix B
func TestMLDSA44RFC9882TestVector(t *testing.T) {
	// Decode the PEM
	block, _ := pem.Decode([]byte(mldsa44SignedData))
	if block == nil {
		t.Fatal("Failed to decode PEM")
	}

	// Parse the signed data
	p7, err := Parse(block.Bytes)
	if err != nil {
		t.Fatalf("Failed to parse signed data: %v", err)
	}

	// Verify the content
	expectedContent := "ML-DSA-44 signed-data example with signed attributes"
	if string(p7.Content) != expectedContent {
		t.Errorf("Content mismatch:\n\tExpected: %s\n\tActual: %s", expectedContent, string(p7.Content))
	}

	// Check that we have one signer
	if len(p7.Signers) != 1 {
		t.Fatalf("Expected 1 signer, got %d", len(p7.Signers))
	}

	signer := p7.Signers[0]

	// Verify digest algorithm is SHA-512 (per RFC 9882)
	expectedDigestOID := asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 3} // SHA-512
	if !signer.DigestAlgorithm.Algorithm.Equal(expectedDigestOID) {
		t.Errorf("Expected digest algorithm SHA-512 (%v), got %v",
			expectedDigestOID, signer.DigestAlgorithm.Algorithm)
	}

	// Verify signature algorithm is ML-DSA-44
	expectedSigOID := asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 3, 17} // ML-DSA-44
	if !signer.DigestEncryptionAlgorithm.Algorithm.Equal(expectedSigOID) {
		t.Errorf("Expected signature algorithm ML-DSA-44 (%v), got %v",
			expectedSigOID, signer.DigestEncryptionAlgorithm.Algorithm)
	}

	// Verify that signed attributes are present
	if len(signer.AuthenticatedAttributes) == 0 {
		t.Error("Expected authenticated attributes to be present")
	}

	// The test vector uses a certificate from RFC 9881 Appendix C
	// We'll use the public key from that certificate for verification
	// For now, we just verify the structure without checking the signature
	// since we don't have the certificate parsed yet

	t.Logf("Successfully parsed ML-DSA-44 signed-data from RFC 9882")
	t.Logf("Signer issuer: %v", signer.IssuerAndSerialNumber.IssuerName)
	t.Logf("Serial number: %v", signer.IssuerAndSerialNumber.SerialNumber)
	t.Logf("Signature length: %d bytes", len(signer.EncryptedDigest))
	t.Logf("Number of authenticated attributes: %d", len(signer.AuthenticatedAttributes))

	// Note: Full verification would require the certificate from RFC 9881 Appendix C
	// For now, this test validates the structure and ensures our parser can handle
	// the RFC 9882 test vector correctly
	if len(p7.Certificates) == 0 {
		cert, err := smx509.ParseCertificatePEM([]byte(mldsa44Cert))
		if err != nil {
			t.Errorf("Failed to parse ML-DSA-44 certificate: %v", err)
		} else {
			t.Logf("Parsed ML-DSA-44 certificate: %v", cert.Subject)
		}
		p7.Certificates = append(p7.Certificates, cert)
	}
	if err := p7.Verify(); err != nil {
		t.Errorf("Failed to verify signed data: %v", err)
	}
}

var mldsa44Cert = `
-----BEGIN CERTIFICATE-----
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
AAAAABcmOEM=
-----END CERTIFICATE-----
`

// This is the example signed-data from RFC 9882 Appendix B
// It contains an ML-DSA-44 signature with signed attributes
var mldsa44SignedData = `
-----BEGIN CMS-----
MIIKsAYJKoZIhvcNAQcCoIIKoTCCCp0CAQExDTALBglghkgBZQMEAgMwQwYJKoZI
hvcNAQcBoDYENE1MLURTQS00NCBzaWduZWQtZGF0YSBleGFtcGxlIHdpdGggc2ln
bmVkIGF0dHJpYnV0ZXMxggpCMIIKPgIBATA6MCIxDTALBgNVBAoTBElFVEYxETAP
BgNVBAMTCExBTVBTIFdHAhQVn/5vIv1cxCxSTfb9XijQ3jjzTjALBglghkgBZQME
AgOgazAYBgkqhkiG9w0BCQMxCwYJKoZIhvcNAQcBME8GCSqGSIb3DQEJBDFCBEAL
v5NoEkfE3OkMRW4rKXw97hdFLivtQ/OVU4Pc/DrfWm3d7POpIxNQ4WCwyGDTWKwi
dWwcHZ9E3CT0Twj2gI/UMAsGCWCGSAFlAwQDEQSCCXTzX9ZSUYiiAjJ2USF/0b1K
fyTnaJTCFymSXY/ZOE0++0F6BZ9HUQweqTlrfXUmpOLlYK+8Hd/zCmyjboKZZmCA
KY4rPlbI4W9ndcowgSgawGixVsOvOBimudg4B5Tbo43cORwIPW6FdDrCa9eKgcGh
bMIFTYFF7f9J3suzYmcj7H99nDJd3d9POqPW0J2NWz64UoxZP8iHOu78gd46yIwB
Rz9VYerDOBSOkZiU2kQUXGhCKmOogOES8Vg1TfV3esn7xeLbOhn4uyrpSOBx5bdC
3BLRxvWdic+haOSFQns5uSrduRjXTaLi88tnVWknzfidCzKubzIxJ/7CMcEcXxu+
L+dUOVXZvATV3FIddk9re8x54Z7gb0kHEyemJnf9uq+084pGB/LrIH5x+ZyYdzlZ
Ys1a7XqEONK/VIuwD2E7UHcYDSROZAYRMFGoyqGKdwVD6/W1ElDYND6eX7Vqss4H
jDuDi7qsha2j4oHet5JQWYeCSxSUsmwp+5E9S6p3g/30w4iAlEGQLGZV1H76m+4+
JYWnHapiFFPQ4nxly+C6c6+hDaX+KONzdM/lt0eaJnxq9Nzrprw/ieIqX8A7Ov9t
1MLVwd7W8Gc4auZec/8WrnDI/f7qaSU0Kt+kNN0oK2maZvLYbDyaDSlUyK4IXvqA
FR5fbSgFmy7SY2TDc4k8JJ/KdBqSg8k0/tRemBiXE/YfltddyZqsD+vhoz5RXhl0
DvyZbQwxW67bdgr6TgRKexRuWOQTR9CAWNitmPzmZDRqIxIhtbg3jtoXuJTg4OO3
/tjhr+ZxCv5zsgcbUiJBiCsHRhuc1W1erOCRu+fknwXZBgF73WtFhDfDq8u9a00e
jBTW4xMAXVfv3coIaknsDP+Di9LtvsXxhLsMaRr9bFZnfhcfU4/O0w+rGWbZ8l14
y8ECh//OPjYQxmFvXaqV9r2Fz6KkslzwlerMq/MjFUjt6vNcxHaGEID/m+xzSJAB
5/BzW0qkIBFoWIDHTkYo9wie7QI6cbgM7qbpTxJAbauPU0VYf2VUTTuGxVtb4aNQ
zMDYSBjHVDjZ3/o+kmkjrlBxl+Jvx7QelOGOVNhKMP7OwMIXj50txvWqRVlTXIvm
p5Qv/NFJWQTJWDv608Mt5/4lbGqJBO7v9T7gfxvd1LWXmmd1X/T8oPg9rFI6rGNP
Nz7xoxs8xkAa+sBcoPmNQyk9q9srER8Fwi3eBGnUFuAq8nKfn+2LXh/Iuhxk6BFc
a1wC4Qa5PV4uiKjsUrKyWwux12Z3dAbtLIf9HNStu1l57KaiJ/XLkCsUsDVAcq8L
GJHpuT0OOY/2Ai/JkE6CjJH9nEXQLgxWHadD0gJrQA8rnwVOccex7RjX7xkhh/0d
b3HxLf2fOFt6lyWgFK1uZKpLrp1fk6+U1hxk+EuUfdayrTOt5poNolRXaohINP7m
ZZj1yqGhWlbq0xkZt7xantZ5FB1QuT9hT5FiY4TFoB1Z5LJlXvLpM/QFB/4n9ZJi
fqqjKA6wMCWxBpsu4+ZOfaQkwvRZ+9+O8QIMlQaRqyMoZeSVh622QmUjuAw7EyYY
KRR/sPkLe1SFXwFg6mcqrnABRGy2kHs2a63j4MIpev1DonKNWPbbBSzkqncPYpb6
MHXQTiL1/uqbl/vUElNucQxvzsaCIDP0ULQiZLS5PUO18rjWa3BbEOner4MyAT2s
QXj5fxHYmuT69JppafV9omZa30d2mUDDtz9Wy2xGRE8MvSrawsRNE5Hucc/tXZul
BzOGPARtzKB3lgrXuQU9CyYSM3T387tM1o1AXmOJO/H4bhAbAqFeFnL1Wm/gFWFr
ocpVPNwAWRQj7NdteRMX/qE8nWMjGl1ax7wl3BPa8pDwC+6lpnVfGDzBNlwBzTHz
oXtjGTTRuFi1Zpy6BgvAPuVZcxXC6Pg8EeodO1XH4pPKtPJ+tkCWLrnxzMur7oAP
i5P3UZ/AEXrLiMw/f6oltVVDWvGD9T5OeemgB4fRzSG/0Sxu1WpMBm1va1v56Gym
UOu59MHb6jR2NpsGBRu1J/5FVoxghvitSA4ggAhkLmlndoNcW0ThHJx67WBJH78h
gVHhjqBuaXwRlfocyqdrNw4B9iVAEx/sxldvF9pIvlsnRXKore8RF9p40fYz7GGc
2+cbtdgCVyfpnt2u2reyvPgOAzw/Moms+AXs+LaxzHt6mrWIJOsuNtLwrwTEJu1t
GkQiBwZwDlG+wb885YvMxAoAXU9s88jSWzEyfUS4ksMgG2CVrmfewHeFuLIFR9D1
LZkFSmQTgWLKwdJw73XUgFOqHxzMTBkLoTAIQasTZKjC16OzCbwZv5e/PT7hqvQk
ic07PJLIjA41uhGnSyaN2ELYQYKQFcTAky5eHYaDHdJgMZTTKMn+k1SHYHCBYkzH
ToSoodOW7ezgjzkMJMAp3A/egYFrCHpOdmiCkE6ot2OCW8Ju9vxKQMWAXXelFOa7
j3tVSqIUdvTjzyAGINsVU8ihKaSStO8khnOftb/aUj7eN36FHMwMeNH2LhXbwSJI
++u4GWW3woD8ZUyo1mpH7xLmBrci7Phs7gFpHtJeIZpPBeG5MuEDpvzCHHBBrvUA
Ek8zuLLGYdlbb2PWGM6A3M+efSnjaY6JQS3GURQLA9BWMtuS5L3+ytm0FOOwOVCA
hq2BN+vNwXm1XWqlEG1sbpAUbngWkpyipUT3GBBvjp+Ak3RIlciLQGcZ1IlXeg1E
W9K8YhhLo49Oh3GDuf4CZgPULsHXqKcCr9lVDpff/kcxwVeXITQiFVykwjfEllXT
gnxR3zQRP61P3aisQxwsaKgHKGzD5idGAzGQuwVgAs95xA/ka1ccMe8a5da+bKP/
9QqnAFFtArVZpso0Xcy2D/iusW2bcBjiSANM4GnZwsyphF0WIK89aq/411WIz3zc
XflJIW80fAy47VF8W340bSgc24AOrQlz38TEGLIcvqPvSMTQRVUdl2S9PgGo8cpP
J5+lm7FzJftRSTwYsaSwtOUM1hvvXbvcWfO3g8XMJbof8cWH7QeEPcan+ygxqbtt
ArQ5Dk+BE4Rv/MBJUVi5E30IBHxWXx6OTwSljFDjBwt8bPVk7YMaBWMMY4KZw5jU
nRakavONHDQDizfy7U0IRAEjKTxKTFaRk56+y839PF2Tlp63wO0UFzAyQVVkZ2uR
zs/Q7xYbHEBpepGfq7C0w9Tp7fgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
DhYkNA==
-----END CMS-----
`
