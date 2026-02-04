// Copyright 2024 The gmsm Authors. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

package smx509

import (
	"crypto/ecdsa"
	"math/big"
	"os"
	"testing"

	"github.com/emmansun/gmsm/sm2"
	"golang.org/x/crypto/cryptobyte"
)

func TestParseExplicitCurveCertificate(t *testing.T) {
	// Certificate with explicit SM2 parameters (RFC 3279 format)
	derBytes, err := os.ReadFile("testdata/explicit_curve_cert.der")
	if err != nil {
		t.Fatalf("failed to read test certificate: %v", err)
	}

	cert, err := ParseCertificate(derBytes)
	if err != nil {
		t.Fatalf("ParseCertificate failed: %v", err)
	}

	pubKey, ok := cert.PublicKey.(*ecdsa.PublicKey)
	if !ok {
		t.Fatalf("expected *ecdsa.PublicKey, got %T", cert.PublicKey)
	}

	if pubKey.Curve != sm2.P256() {
		t.Errorf("expected SM2 P-256 curve, got %v", pubKey.Curve.Params().Name)
	}

	if cert.PublicKeyAlgorithm != ECDSA {
		t.Errorf("expected ECDSA public key algorithm, got %v", cert.PublicKeyAlgorithm)
	}

	if cert.SignatureAlgorithm != SM2WithSM3 {
		t.Errorf("expected SM2-SM3 signature algorithm, got %v", cert.SignatureAlgorithm)
	}

	if err := cert.CheckSignatureFrom(cert); err != nil {
		t.Errorf("signature verification failed: %v", err)
	}

	if cert.Subject.CommonName != "Chenglitong Ceshi" {
		t.Errorf("unexpected subject CN: %s", cert.Subject.CommonName)
	}

	if cert.Issuer.CommonName != "Chenglitong Ceshi" {
		t.Errorf("unexpected issuer CN: %s", cert.Issuer.CommonName)
	}

	if !cert.IsCA {
		t.Error("expected CA certificate")
	}
}

func TestParseExplicitCurveInvalidPoint(t *testing.T) {
	// Construct a certificate with valid explicit curve but invalid public key point
	derBytes, err := os.ReadFile("testdata/explicit_curve_cert.der")
	if err != nil {
		t.Fatalf("failed to read test certificate: %v", err)
	}

	// Corrupt the public key point (bytes around offset 0x175)
	// This makes the curve parameters valid but the point invalid
	corrupted := make([]byte, len(derBytes))
	copy(corrupted, derBytes)

	// Find and corrupt the public key BIT STRING
	// The public key point starts with 0x04 (uncompressed point)
	for i := 0; i < len(corrupted)-10; i++ {
		if corrupted[i] == 0x03 && corrupted[i+1] == 0x42 && corrupted[i+2] == 0x00 && corrupted[i+3] == 0x04 {
			// Found the BIT STRING containing the public key point
			// Corrupt the point data to make it invalid
			corrupted[i+4] = 0xFF
			corrupted[i+5] = 0xFF
			break
		}
	}

	_, err = ParseCertificate(corrupted)
	if err == nil {
		t.Error("should reject certificate with invalid public key point")
	}
	if err != nil && err.Error() != "x509: failed to unmarshal elliptic curve point" {
		t.Logf("got error: %v", err)
	}
}

func TestMatchKnownCurve(t *testing.T) {
	tests := []struct {
		name    string
		p       string
		n       string
		wantErr bool
	}{
		{
			name:    "SM2 P-256",
			p:       "FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFF",
			n:       "FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF7203DF6B21C6052B53BBF40939D54123",
			wantErr: false,
		},
		{
			name:    "NIST P-256",
			p:       "FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF",
			n:       "FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551",
			wantErr: false,
		},
		{
			name:    "NIST P-384",
			p:       "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFF0000000000000000FFFFFFFF",
			n:       "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFC7634D81F4372DDF581A0DB248B0A77AECEC196ACCC52973",
			wantErr: false,
		},
		{
			name:    "NIST P-521",
			p:       "01FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF",
			n:       "01FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFA51868783BF2F966B7FCC0148F709A5D03BB5C9B8899C47AEBB6FB71E91386409",
			wantErr: false,
		},
		{
			name:    "wrong prime",
			p:       "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF",
			n:       "FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF7203DF6B21C6052B53BBF40939D54123",
			wantErr: true,
		},
		{
			name:    "wrong order",
			p:       "FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFF",
			n:       "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF",
			wantErr: true,
		},
		{
			name:    "unknown parameters",
			p:       "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF",
			n:       "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := hexToBigInt(t, tt.p)
			n := hexToBigInt(t, tt.n)

			curve, err := matchKnownCurve(p, n)
			if tt.wantErr {
				if err == nil {
					t.Error("expected error, got nil")
				}
			} else {
				if err != nil {
					t.Errorf("unexpected error: %v", err)
				}
				if curve == nil {
					t.Error("expected curve, got nil")
				}
			}
		})
	}
}

func TestParseECDSAExplicitFallback(t *testing.T) {
	// Test that ECDSA key parsing falls back to explicit curve when named curve fails
	// This tests the fallback logic in parser.go

	t.Run("valid explicit curve after named curve fails", func(t *testing.T) {
		// Use the test certificate which has explicit parameters
		derBytes, err := os.ReadFile("testdata/explicit_curve_cert.der")
		if err != nil {
			t.Fatalf("failed to read test certificate: %v", err)
		}

		cert, err := ParseCertificate(derBytes)
		if err != nil {
			t.Fatalf("ParseCertificate should succeed: %v", err)
		}

		if _, ok := cert.PublicKey.(*ecdsa.PublicKey); !ok {
			t.Errorf("expected ECDSA public key")
		}
	})

	t.Run("neither named curve nor explicit params work", func(t *testing.T) {
		// Construct invalid ECDSA parameters (not a valid OID or explicit params)
		derBytes, err := os.ReadFile("testdata/explicit_curve_cert.der")
		if err != nil {
			t.Fatalf("failed to read test certificate: %v", err)
		}

		corrupted := make([]byte, len(derBytes))
		copy(corrupted, derBytes)

		// Find the algorithm parameters SEQUENCE and corrupt it
		// Look for the explicit curve parameters SEQUENCE (starts with 0x30 0x81 0xec)
		for i := 0; i < len(corrupted)-3; i++ {
			if corrupted[i] == 0x30 && corrupted[i+1] == 0x81 && corrupted[i+2] == 0xec {
				// Corrupt the SEQUENCE to make it invalid
				corrupted[i] = 0x05 // Change to NULL tag
				corrupted[i+1] = 0x00
				break
			}
		}

		_, err = ParseCertificate(corrupted)
		if err == nil {
			t.Error("should reject certificate with invalid ECDSA parameters")
		}
	})
}

func TestParseExplicitECParameters(t *testing.T) {
	t.Run("invalid version", func(t *testing.T) {
		data := []byte{
			0x30, 0x0a,
			0x02, 0x01, 0x02, // version = 2
			0x30, 0x05, 0x06, 0x03, 0x2a, 0x03, 0x04,
		}
		params := cryptobyte.String(data)
		_, err := parseExplicitECParameters(params)
		if err == nil {
			t.Error("should reject version != 1")
		}
	})

	t.Run("truncated data", func(t *testing.T) {
		data := []byte{0x30, 0x03, 0x02, 0x01}
		params := cryptobyte.String(data)
		_, err := parseExplicitECParameters(params)
		if err == nil {
			t.Error("should reject incomplete data")
		}
	})

	t.Run("missing fieldID", func(t *testing.T) {
		data := []byte{
			0x30, 0x03,
			0x02, 0x01, 0x01,
		}
		params := cryptobyte.String(data)
		_, err := parseExplicitECParameters(params)
		if err == nil {
			t.Error("should reject missing fieldID")
		}
	})

	t.Run("invalid fieldType OID", func(t *testing.T) {
		data := []byte{
			0x30, 0x0c,
			0x02, 0x01, 0x01, // version = 1
			0x30, 0x07,
			0x06, 0x02, 0xff, 0xff, // invalid OID
			0x02, 0x01, 0x05, // dummy prime
		}
		params := cryptobyte.String(data)
		_, err := parseExplicitECParameters(params)
		if err == nil {
			t.Error("should reject invalid fieldType OID")
		}
	})

	t.Run("invalid prime", func(t *testing.T) {
		data := []byte{
			0x30, 0x10,
			0x02, 0x01, 0x01, // version = 1
			0x30, 0x0b,
			0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x01, 0x01, // prime-field OID
			0x05, 0x00, // NULL instead of INTEGER
		}
		params := cryptobyte.String(data)
		_, err := parseExplicitECParameters(params)
		if err == nil {
			t.Error("should reject invalid prime")
		}
	})

	t.Run("invalid curve coefficients", func(t *testing.T) {
		data := []byte{
			0x30, 0x1a,
			0x02, 0x01, 0x01, // version = 1
			0x30, 0x0d,
			0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x01, 0x01, // prime-field OID
			0x02, 0x02, 0x00, 0xff, // prime
			0x30, 0x06,
			0x04, 0x01, 0x00, // only one coefficient (need two)
			0x05, 0x00, // NULL instead of second OCTET STRING
		}
		params := cryptobyte.String(data)
		_, err := parseExplicitECParameters(params)
		if err == nil {
			t.Error("should reject invalid curve coefficients")
		}
	})

	t.Run("invalid base point", func(t *testing.T) {
		data := []byte{
			0x30, 0x20,
			0x02, 0x01, 0x01, // version = 1
			0x30, 0x0d,
			0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x01, 0x01,
			0x02, 0x02, 0x00, 0xff,
			0x30, 0x06,
			0x04, 0x01, 0x00,
			0x04, 0x01, 0x01,
			0x05, 0x00, // NULL instead of OCTET STRING base point
		}
		params := cryptobyte.String(data)
		_, err := parseExplicitECParameters(params)
		if err == nil {
			t.Error("should reject invalid base point")
		}
	})

	t.Run("invalid order", func(t *testing.T) {
		data := []byte{
			0x30, 0x25,
			0x02, 0x01, 0x01, // version = 1
			0x30, 0x0d,
			0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x01, 0x01,
			0x02, 0x02, 0x00, 0xff,
			0x30, 0x06,
			0x04, 0x01, 0x00,
			0x04, 0x01, 0x01,
			0x04, 0x03, 0x00, 0x00, 0x01, // base point
			0x05, 0x00, // NULL instead of INTEGER order
		}
		params := cryptobyte.String(data)
		_, err := parseExplicitECParameters(params)
		if err == nil {
			t.Error("should reject invalid order")
		}
	})
}

func hexToBigInt(t *testing.T, s string) *big.Int {
	t.Helper()
	i := new(big.Int)
	i.SetString(s, 16)
	return i
}
