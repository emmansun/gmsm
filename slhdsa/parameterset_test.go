// Copyright 2025 Sun Yimin. All rights reserved.
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file.

//go:build go1.24

package slhdsa

import (
	"crypto/rand"
	"encoding/asn1"
	"testing"
)

func TestParamsOID(t *testing.T) {
	tests := []struct {
		name      string
		params    *params
		expectOID asn1.ObjectIdentifier
	}{
		{
			name:      "SLH-DSA-SHA2-128s",
			params:    &SLHDSA128SmallSHA2,
			expectOID: asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 3, 20},
		},
		{
			name:      "SLH-DSA-SHA2-128f",
			params:    &SLHDSA128FastSHA2,
			expectOID: asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 3, 21},
		},
		{
			name:      "SLH-DSA-SHA2-192s",
			params:    &SLHDSA192SmallSHA2,
			expectOID: asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 3, 22},
		},
		{
			name:      "SLH-DSA-SHA2-192f",
			params:    &SLHDSA192FastSHA2,
			expectOID: asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 3, 23},
		},
		{
			name:      "SLH-DSA-SHA2-256s",
			params:    &SLHDSA256SmallSHA2,
			expectOID: asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 3, 24},
		},
		{
			name:      "SLH-DSA-SHA2-256f",
			params:    &SLHDSA256FastSHA2,
			expectOID: asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 3, 25},
		},
		{
			name:      "SLH-DSA-SHAKE-128s",
			params:    &SLHDSA128SmallSHAKE,
			expectOID: asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 3, 26},
		},
		{
			name:      "SLH-DSA-SHAKE-128f",
			params:    &SLHDSA128FastSHAKE,
			expectOID: asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 3, 27},
		},
		{
			name:      "SLH-DSA-SHAKE-192s",
			params:    &SLHDSA192SmallSHAKE,
			expectOID: asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 3, 28},
		},
		{
			name:      "SLH-DSA-SHAKE-192f",
			params:    &SLHDSA192FastSHAKE,
			expectOID: asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 3, 29},
		},
		{
			name:      "SLH-DSA-SHAKE-256s",
			params:    &SLHDSA256SmallSHAKE,
			expectOID: asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 3, 30},
		},
		{
			name:      "SLH-DSA-SHAKE-256f",
			params:    &SLHDSA256FastSHAKE,
			expectOID: asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 3, 31},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			oid := tt.params.OID()
			if !oid.Equal(tt.expectOID) {
				t.Errorf("OID mismatch for %s: got %v, want %v", tt.name, oid, tt.expectOID)
			}
		})
	}
}

func TestParamsString(t *testing.T) {
	tests := []struct {
		params *params
		expect string
	}{
		{&SLHDSA128SmallSHA2, "SLH-DSA-SHA2-128s"},
		{&SLHDSA128FastSHA2, "SLH-DSA-SHA2-128f"},
		{&SLHDSA192SmallSHA2, "SLH-DSA-SHA2-192s"},
		{&SLHDSA192FastSHA2, "SLH-DSA-SHA2-192f"},
		{&SLHDSA256SmallSHA2, "SLH-DSA-SHA2-256s"},
		{&SLHDSA256FastSHA2, "SLH-DSA-SHA2-256f"},
		{&SLHDSA128SmallSHAKE, "SLH-DSA-SHAKE-128s"},
		{&SLHDSA128FastSHAKE, "SLH-DSA-SHAKE-128f"},
		{&SLHDSA192SmallSHAKE, "SLH-DSA-SHAKE-192s"},
		{&SLHDSA192FastSHAKE, "SLH-DSA-SHAKE-192f"},
		{&SLHDSA256SmallSHAKE, "SLH-DSA-SHAKE-256s"},
		{&SLHDSA256FastSHAKE, "SLH-DSA-SHAKE-256f"},
	}

	for _, tt := range tests {
		t.Run(tt.expect, func(t *testing.T) {
			if got := tt.params.String(); got != tt.expect {
				t.Errorf("String() = %v, want %v", got, tt.expect)
			}
		})
	}
}

func TestPublicKeyOID(t *testing.T) {
	// Test that PublicKey.OID() returns the correct OID
	pk, err := SLHDSA128SmallSHA2.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey failed: %v", err)
	}

	expectedOID := asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 3, 20}
	gotOID := pk.PublicKey.OID()

	if !gotOID.Equal(expectedOID) {
		t.Errorf("PublicKey.OID() = %v, want %v", gotOID, expectedOID)
	}
}
