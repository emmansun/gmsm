// Copyright 2026 Sun Yimin. All rights reserved.
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file.

package sm2

import (
	"crypto/subtle"
	"encoding/hex"
	"errors"

	"github.com/emmansun/gmsm/internal/sm2ec"
)

// KAT private key bytes (0x1234567890abcdef repeated four times).
var katPrivKeyBytes = []byte{
	0x12, 0x34, 0x56, 0x78, 0x90, 0xab, 0xcd, 0xef,
	0x12, 0x34, 0x56, 0x78, 0x90, 0xab, 0xcd, 0xef,
	0x12, 0x34, 0x56, 0x78, 0x90, 0xab, 0xcd, 0xef,
	0x12, 0x34, 0x56, 0x78, 0x90, 0xab, 0xcd, 0xef,
}

// KAT message.
var katMsg = []byte("sm2 self-test message")

// KAT expected deterministic signature (RFC 6979 + HMAC-SM3) components.
var (
	katExpectedR = "8c2abadad0e0bc5e84a78be75f480d643832563aee35aeea76aa2dbd4f5c6c92"
	katExpectedS = "7f4ddc0f44f511481cf05a8bd6749dea16152e553d0a8483a801a734c9b3c4bc"
)

// KATSignDeterministic verifies SM2 deterministic signing (RFC 6979 + HMAC-SM3) and verification.
func KATSignDeterministic() error {
	// Compute public key point from private key.
	q, err := sm2ec.NewSM2P256Point().ScalarBaseMult(katPrivKeyBytes)
	if err != nil {
		return errors.New("failed to compute public key: " + err.Error())
	}

	priv, err := NewPrivateKey(katPrivKeyBytes, q.Bytes())
	if err != nil {
		return errors.New("failed to create private key: " + err.Error())
	}

	// Sign deterministically.
	sig, err := SignDeterministic(priv, katMsg)
	if err != nil {
		return errors.New("deterministic sign failed: " + err.Error())
	}

	// Compare R.
	wantR, _ := hex.DecodeString(katExpectedR)
	if subtle.ConstantTimeCompare(sig.R, wantR) != 1 {
		return errors.New("deterministic signature R mismatch")
	}

	// Compare S.
	wantS, _ := hex.DecodeString(katExpectedS)
	if subtle.ConstantTimeCompare(sig.S, wantS) != 1 {
		return errors.New("deterministic signature S mismatch")
	}

	// Verify must accept the known-good signature.
	if err := Verify(priv.PublicKey(), katMsg, sig); err != nil {
		return errors.New("KAT signature verification failed: " + err.Error())
	}

	// Verify must reject a tampered signature (flip one bit in S).
	tampered := &Signature{R: make([]byte, len(sig.R)), S: make([]byte, len(sig.S))}
	copy(tampered.R, sig.R)
	copy(tampered.S, sig.S)
	tampered.S[len(tampered.S)-1] ^= 0x01
	if err := Verify(priv.PublicKey(), katMsg, tampered); err == nil {
		return errors.New("tampered signature incorrectly verified")
	}

	return nil
}
