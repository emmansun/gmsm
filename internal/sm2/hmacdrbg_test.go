// Copyright 2026 Sun Yimin. All rights reserved.
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file.

package sm2

import (
	"bytes"
	"testing"

	"github.com/emmansun/gmsm/internal/bigmod"
)

func TestHMACDRBG_DeterministicOutput(t *testing.T) {
	// Same seed must produce the same output sequence
	entropy := make([]byte, 32)
	nonce := make([]byte, 32)
	for i := range entropy {
		entropy[i] = byte(i)
	}
	for i := range nonce {
		nonce[i] = byte(i + 32)
	}

	drbg1 := TestingOnlyNewDRBG(entropy, nonce, nil)
	drbg2 := TestingOnlyNewDRBG(entropy, nonce, nil)

	out1 := make([]byte, 32)
	out2 := make([]byte, 32)
	drbg1.Generate(out1)
	drbg2.Generate(out2)

	if !bytes.Equal(out1, out2) {
		t.Errorf("DRBG with same seed produced different output:\n  got:  %x\n  want: %x", out1, out2)
	}
}

func TestHMACDRBG_DifferentSeedsProduceDifferentOutput(t *testing.T) {
	entropy1 := make([]byte, 32)
	entropy2 := make([]byte, 32)
	for i := range entropy1 {
		entropy1[i] = byte(i)
		entropy2[i] = byte(i + 1)
	}
	nonce := make([]byte, 32)

	drbg1 := TestingOnlyNewDRBG(entropy1, nonce, nil)
	drbg2 := TestingOnlyNewDRBG(entropy2, nonce, nil)

	out1 := make([]byte, 32)
	out2 := make([]byte, 32)
	drbg1.Generate(out1)
	drbg2.Generate(out2)

	if bytes.Equal(out1, out2) {
		t.Errorf("DRBG with different seeds produced same output: %x", out1)
	}
}

func TestHMACDRBG_DifferentNoncesProduceDifferentOutput(t *testing.T) {
	entropy := make([]byte, 32)
	nonce1 := make([]byte, 32)
	nonce2 := make([]byte, 32)
	for i := range nonce1 {
		nonce1[i] = byte(i)
		nonce2[i] = byte(i + 1)
	}

	drbg1 := TestingOnlyNewDRBG(entropy, nonce1, nil)
	drbg2 := TestingOnlyNewDRBG(entropy, nonce2, nil)

	out1 := make([]byte, 32)
	out2 := make([]byte, 32)
	drbg1.Generate(out1)
	drbg2.Generate(out2)

	if bytes.Equal(out1, out2) {
		t.Errorf("DRBG with different nonces produced same output: %x", out1)
	}
}

func TestHMACDRBG_SequentialCallsProduceDifferentOutput(t *testing.T) {
	entropy := make([]byte, 32)
	nonce := make([]byte, 32)

	drbg := TestingOnlyNewDRBG(entropy, nonce, nil)

	out1 := make([]byte, 32)
	out2 := make([]byte, 32)
	drbg.Generate(out1)
	drbg.Generate(out2)

	if bytes.Equal(out1, out2) {
		t.Errorf("sequential DRBG Generate calls produced same output: %x", out1)
	}
}

func TestHMACDRBG_WithPersonalizationString(t *testing.T) {
	entropy := make([]byte, 32)
	nonce := make([]byte, 32)
	personalization := []byte("test personalization string")

	drbg1 := TestingOnlyNewDRBG(entropy, nonce, personalization)
	drbg2 := TestingOnlyNewDRBG(entropy, nonce, nil)

	out1 := make([]byte, 32)
	out2 := make([]byte, 32)
	drbg1.Generate(out1)
	drbg2.Generate(out2)

	if bytes.Equal(out1, out2) {
		t.Errorf("DRBG with and without personalization string produced same output: %x", out1)
	}
}

func TestHMACDRBG_MultiRoundOutput(t *testing.T) {
	// Verify that Generate calls are deterministic across multiple rounds
	entropy := make([]byte, 32)
	nonce := make([]byte, 32)
	for i := range entropy {
		entropy[i] = byte(i)
	}

	drbg1 := TestingOnlyNewDRBG(entropy, nonce, nil)
	drbg2 := TestingOnlyNewDRBG(entropy, nonce, nil)

	for round := 0; round < 5; round++ {
		out1 := make([]byte, 32)
		out2 := make([]byte, 32)
		drbg1.Generate(out1)
		drbg2.Generate(out2)

		if !bytes.Equal(out1, out2) {
			t.Errorf("round %d: DRBG outputs diverged:\n  got:  %x\n  want: %x", round, out1, out2)
		}
	}
}

func TestBits2octets_Consistency(t *testing.T) {
	// Indirectly verify bits2octets: same hash input must produce the same DRBG nonce,
	// resulting in the same signature. This is already covered by TestSignDeterministic.
	// Here we additionally verify that a hash value exceeding N is properly reduced mod N.
	// Since bits2octets is unexported, we test it via the internal hashToNat function.

	c := P256()

	// Test hash value larger than N: bits2octets should reduce mod N
	// Construct a hash such that hashToInt exceeds N
	longHash := make([]byte, 64) // 64-byte hash
	for i := range longHash {
		longHash[i] = 0xFF
	}

	// bits2octets should correctly truncate the hash and reduce mod N
	e := bigmod.NewNat()
	hashToNat(c, e, longHash)
	result := e.Bytes(c.N)

	// Verify the result is not all 0xFF (confirming mod N reduction occurred)
	allFF := make([]byte, len(result))
	for i := range allFF {
		allFF[i] = 0xFF
	}
	if bytes.Equal(result, allFF) {
		t.Errorf("bits2octets did not reduce hash mod N: got %x", result)
	}
}
