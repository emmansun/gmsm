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
}

func hexToBigInt(t *testing.T, s string) *big.Int {
	t.Helper()
	i := new(big.Int)
	i.SetString(s, 16)
	return i
}
