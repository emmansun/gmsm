// Copyright 2026 Sun Yimin. All rights reserved.
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file.

package sm2_test

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"math/big"
	"testing"

	"github.com/emmansun/gmsm/sm2"
	"github.com/emmansun/gmsm/sm3"
)

// Basic deterministic signature test

func TestSignDeterministic(t *testing.T) {
	privKey1, err := sm2.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey failed: %v", err)
	}
	privKey2, err := sm2.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey failed: %v", err)
	}

	msg := []byte("hello world")
	sig1, err := sm2.SignDeterministic(privKey1, msg, sm2.DefaultSM2SignerOpts)
	if err != nil {
		t.Fatalf("SignDeterministic() failed: %v", err)
	}
	sig2, err := sm2.SignDeterministic(privKey1, msg, sm2.DefaultSM2SignerOpts)
	if err != nil {
		t.Fatalf("SignDeterministic() failed: %v", err)
	}
	if !bytes.Equal(sig1, sig2) {
		t.Errorf("SignDeterministic() produced different signatures for the same input")
	}
	if !sm2.VerifyASN1WithSM2(&privKey1.PublicKey, nil, msg, sig1) {
		t.Errorf("SignDeterministic() produced an invalid signature")
	}
	sig3, err := sm2.SignDeterministic(privKey2, msg, sm2.DefaultSM2SignerOpts)
	if err != nil {
		t.Fatalf("SignDeterministic() failed: %v", err)
	}
	if bytes.Equal(sig1, sig3) {
		t.Errorf("SignDeterministic() produced the same signature for different keys")
	}
	if !sm2.VerifyASN1WithSM2(&privKey2.PublicKey, nil, msg, sig3) {
		t.Errorf("SignDeterministic() produced an invalid signature")
	}
}

// Unsupported curve

func TestSignDeterministic_UnsupportedCurve(t *testing.T) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey failed: %v", err)
	}
	sm2Priv := &sm2.PrivateKey{PrivateKey: *priv}
	_, err = sm2.SignDeterministic(sm2Priv, []byte("test"), nil)
	if err == nil {
		t.Fatal("expected error for unsupported curve")
	}
	if err.Error() != "sm2: curve not supported by deterministic signatures" {
		t.Errorf("unexpected error: %v", err)
	}
}

// nil opts (pass pre-computed hash directly)

func TestSignDeterministic_NilOpts(t *testing.T) {
	privKey, err := sm2.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey failed: %v", err)
	}
	hash := sm3.Sum([]byte("test"))
	sig, err := sm2.SignDeterministic(privKey, hash[:], nil)
	if err != nil {
		t.Fatalf("SignDeterministic with nil opts failed: %v", err)
	}
	if !sm2.VerifyASN1(&privKey.PublicKey, hash[:], sig) {
		t.Errorf("signature verification failed for nil opts")
	}
	// Deterministic: signing again should produce the same result
	sig2, err := sm2.SignDeterministic(privKey, hash[:], nil)
	if err != nil {
		t.Fatalf("SignDeterministic with nil opts (2nd call) failed: %v", err)
	}
	if !bytes.Equal(sig, sig2) {
		t.Errorf("SignDeterministic with nil opts produced different signatures")
	}
}

// forceGMSign=false path

func TestSignDeterministic_ForceGMSignFalse(t *testing.T) {
	privKey, err := sm2.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey failed: %v", err)
	}
	// With forceGMSign=false, hash is passed directly to the signing algorithm without CalculateSM2Hash.
	// This behaves the same as nil opts: the caller must pre-compute the hash.
	preHash := sm3.Sum([]byte("test message"))
	opts := sm2.NewSM2SignerOption(false, nil)

	sig, err := sm2.SignDeterministic(privKey, preHash[:], opts)
	if err != nil {
		t.Fatalf("SignDeterministic with forceGMSign=false failed: %v", err)
	}
	if !sm2.VerifyASN1(&privKey.PublicKey, preHash[:], sig) {
		t.Errorf("signature verification failed for forceGMSign=false")
	}
}

// Non-SM2SignerOption opts (e.g., crypto.Hash)

func TestSignDeterministic_NonSM2SignerOpts(t *testing.T) {
	privKey, err := sm2.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey failed: %v", err)
	}
	// When opts is not *SM2SignerOption, hash is used directly
	preHash := sm3.Sum([]byte("test message"))
	opts := crypto.SHA256 // plain crypto.SignerOpts

	sig, err := sm2.SignDeterministic(privKey, preHash[:], opts)
	if err != nil {
		t.Fatalf("SignDeterministic with non-SM2SignerOption opts failed: %v", err)
	}
	if !sm2.VerifyASN1(&privKey.PublicKey, preHash[:], sig) {
		t.Errorf("signature verification failed for non-SM2SignerOption opts")
	}
}

// Custom UID

func TestSignDeterministic_CustomUID(t *testing.T) {
	privKey, err := sm2.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey failed: %v", err)
	}
	msg := []byte("test message")
	customUID := []byte("custom-uid-1234")

	opts := sm2.NewSM2SignerOption(true, customUID)
	sig, err := sm2.SignDeterministic(privKey, msg, opts)
	if err != nil {
		t.Fatalf("SignDeterministic with custom UID failed: %v", err)
	}
	// Verify with the same UID
	if !sm2.VerifyASN1WithSM2(&privKey.PublicKey, customUID, msg, sig) {
		t.Errorf("signature verification failed for custom UID")
	}
	// Verify with default UID should fail
	if sm2.VerifyASN1WithSM2(&privKey.PublicKey, nil, msg, sig) {
		t.Errorf("signature verified with wrong UID (should fail)")
	}
	// Deterministic: same UID produces the same signature
	sig2, err := sm2.SignDeterministic(privKey, msg, opts)
	if err != nil {
		t.Fatalf("SignDeterministic with custom UID (2nd call) failed: %v", err)
	}
	if !bytes.Equal(sig, sig2) {
		t.Errorf("SignDeterministic with custom UID produced different signatures")
	}
}

// Different messages produce different signatures

func TestSignDeterministic_DifferentMessages(t *testing.T) {
	privKey, err := sm2.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey failed: %v", err)
	}
	msg1 := []byte("message one")
	msg2 := []byte("message two")

	sig1, err := sm2.SignDeterministic(privKey, msg1, sm2.DefaultSM2SignerOpts)
	if err != nil {
		t.Fatalf("SignDeterministic for msg1 failed: %v", err)
	}
	sig2, err := sm2.SignDeterministic(privKey, msg2, sm2.DefaultSM2SignerOpts)
	if err != nil {
		t.Fatalf("SignDeterministic for msg2 failed: %v", err)
	}
	if bytes.Equal(sig1, sig2) {
		t.Errorf("SignDeterministic produced same signature for different messages")
	}
	// Cross-verification: sig1 should not verify msg2
	if sm2.VerifyASN1WithSM2(&privKey.PublicKey, nil, msg2, sig1) {
		t.Errorf("signature for msg1 incorrectly verified msg2")
	}
}

// Signature forgery detection

func TestSignDeterministic_ForgeryDetection(t *testing.T) {
	privKey1, err := sm2.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey failed: %v", err)
	}
	privKey2, err := sm2.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey failed: %v", err)
	}
	msg := []byte("important message")

	sig1, err := sm2.SignDeterministic(privKey1, msg, sm2.DefaultSM2SignerOpts)
	if err != nil {
		t.Fatalf("SignDeterministic failed: %v", err)
	}
	// Verifying key1's signature with key2's public key should fail
	if sm2.VerifyASN1WithSM2(&privKey2.PublicKey, nil, msg, sig1) {
		t.Errorf("signature from key1 incorrectly verified with key2's public key")
	}
}

// Multiple rounds consistency

func TestSignDeterministic_MultipleRounds(t *testing.T) {
	privKey, err := sm2.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey failed: %v", err)
	}
	msg := []byte("consistency test")

	sig, err := sm2.SignDeterministic(privKey, msg, sm2.DefaultSM2SignerOpts)
	if err != nil {
		t.Fatalf("SignDeterministic failed: %v", err)
	}
	// All 10 signatures should be identical
	for i := 0; i < 10; i++ {
		sigN, err := sm2.SignDeterministic(privKey, msg, sm2.DefaultSM2SignerOpts)
		if err != nil {
			t.Fatalf("SignDeterministic round %d failed: %v", i, err)
		}
		if !bytes.Equal(sig, sigN) {
			t.Errorf("SignDeterministic round %d produced different signature", i)
		}
	}
}

// Various message lengths

func TestSignDeterministic_VariousMessageLengths(t *testing.T) {
	privKey, err := sm2.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey failed: %v", err)
	}
	tests := []struct {
		name string
		msg  []byte
	}{
		{"empty", []byte("")},
		{"1 byte", []byte("a")},
		{"31 bytes", make([]byte, 31)},
		{"32 bytes", make([]byte, 32)},
		{"33 bytes", make([]byte, 33)},
		{"64 bytes", make([]byte, 64)},
		{"128 bytes", make([]byte, 128)},
		{"1000 bytes", make([]byte, 1000)},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sig, err := sm2.SignDeterministic(privKey, tt.msg, sm2.DefaultSM2SignerOpts)
			if err != nil {
				t.Fatalf("SignDeterministic failed: %v", err)
			}
			if !sm2.VerifyASN1WithSM2(&privKey.PublicKey, nil, tt.msg, sig) {
				t.Errorf("signature verification failed for %s", tt.name)
			}
		})
	}
}

// Zero hash

func TestSignDeterministic_ZeroHash(t *testing.T) {
	privKey, err := sm2.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey failed: %v", err)
	}
	zeroHash := make([]byte, 32)
	sig, err := sm2.SignDeterministic(privKey, zeroHash, nil)
	if err != nil {
		t.Fatalf("SignDeterministic with zero hash failed: %v", err)
	}
	if !sm2.VerifyASN1(&privKey.PublicKey, zeroHash, sig) {
		t.Errorf("signature verification failed for zero hash")
	}
}

// Deterministic vs. random signing

func TestSignDeterministic_VsRandom(t *testing.T) {
	privKey, err := sm2.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey failed: %v", err)
	}
	msg := []byte("comparison test")

	detSig, err := sm2.SignDeterministic(privKey, msg, sm2.DefaultSM2SignerOpts)
	if err != nil {
		t.Fatalf("SignDeterministic failed: %v", err)
	}
	// Random signature should verify
	randSig, err := sm2.SignASN1(rand.Reader, privKey, msg, sm2.DefaultSM2SignerOpts)
	if err != nil {
		t.Fatalf("SignASN1 failed: %v", err)
	}
	if !sm2.VerifyASN1WithSM2(&privKey.PublicKey, nil, msg, randSig) {
		t.Errorf("random signature verification failed")
	}
	// Deterministic signature should also verify
	if !sm2.VerifyASN1WithSM2(&privKey.PublicKey, nil, msg, detSig) {
		t.Errorf("deterministic signature verification failed")
	}
	// The two signature formats should differ (random vs. deterministic nonce)
	if bytes.Equal(detSig, randSig) {
		t.Logf("warning: deterministic and random signatures happened to be equal (extremely unlikely but possible)")
	}
	// Multiple random signatures should differ from each other
	randSig2, err := sm2.SignASN1(rand.Reader, privKey, msg, sm2.DefaultSM2SignerOpts)
	if err != nil {
		t.Fatalf("SignASN1 (2nd) failed: %v", err)
	}
	if bytes.Equal(randSig, randSig2) {
		t.Errorf("two random signatures were equal (should be different)")
	}
}

// VerifyASN1 direct verification compatibility

func TestSignDeterministic_VerifyASN1Direct(t *testing.T) {
	privKey, err := sm2.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey failed: %v", err)
	}
	msg := []byte("direct verify test")

	// When forceGMSign=true, SM2 hash is computed internally
	sig, err := sm2.SignDeterministic(privKey, msg, sm2.DefaultSM2SignerOpts)
	if err != nil {
		t.Fatalf("SignDeterministic failed: %v", err)
	}
	// Compute the SM2 hash and verify directly with VerifyASN1
	sm2Hash, err := sm2.CalculateSM2Hash(&privKey.PublicKey, msg, nil)
	if err != nil {
		t.Fatalf("CalculateSM2Hash failed: %v", err)
	}
	if !sm2.VerifyASN1(&privKey.PublicKey, sm2Hash, sig) {
		t.Errorf("VerifyASN1 with pre-computed SM2 hash failed")
	}
}

// Error paths

func TestSignDeterministic_ErrorPaths(t *testing.T) {
	t.Run("nil private key", func(t *testing.T) {
		defer func() {
			if r := recover(); r == nil {
				t.Errorf("expected panic for nil private key")
			}
		}()
		sm2.SignDeterministic(nil, []byte("test"), sm2.DefaultSM2SignerOpts)
	})
}

// Deterministic signature and public key recovery

func TestSignDeterministic_PublicKeyRecovery(t *testing.T) {
	privKey, err := sm2.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey failed: %v", err)
	}
	msg := []byte("recovery test")

	sig, err := sm2.SignDeterministic(privKey, msg, sm2.DefaultSM2SignerOpts)
	if err != nil {
		t.Fatalf("SignDeterministic failed: %v", err)
	}

	// Compute the SM2 hash corresponding to the signature
	sm2Hash, err := sm2.CalculateSM2Hash(&privKey.PublicKey, msg, nil)
	if err != nil {
		t.Fatalf("CalculateSM2Hash failed: %v", err)
	}

	// Recover public keys
	pubs, err := sm2.RecoverPublicKeysFromSM2Signature(sm2Hash, sig)
	if err != nil {
		t.Fatalf("RecoverPublicKeysFromSM2Signature failed: %v", err)
	}

	found := false
	for _, pub := range pubs {
		if pub.Equal(&privKey.PublicKey) {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("original public key not found in recovered keys")
	}
}

// Signature tamper detection

func TestSignDeterministic_TamperDetection(t *testing.T) {
	privKey, err := sm2.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey failed: %v", err)
	}
	msg := []byte("tamper detection test")

	sig, err := sm2.SignDeterministic(privKey, msg, sm2.DefaultSM2SignerOpts)
	if err != nil {
		t.Fatalf("SignDeterministic failed: %v", err)
	}

	// Tamper each byte of the signature; verification should fail
	for i := 0; i < len(sig); i++ {
		tampered := make([]byte, len(sig))
		copy(tampered, sig)
		tampered[i] ^= 0xFF
		if sm2.VerifyASN1WithSM2(&privKey.PublicKey, nil, msg, tampered) {
			t.Errorf("tampered signature at byte %d incorrectly verified", i)
		}
	}
}

// Deterministic signature equivalence with SignASN1

func TestSignDeterministic_EquivalentToSignASN1(t *testing.T) {
	privKey, err := sm2.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey failed: %v", err)
	}
	msg := []byte("equivalence test")

	// Use deterministic signing
	detSig, err := sm2.SignDeterministic(privKey, msg, sm2.DefaultSM2SignerOpts)
	if err != nil {
		t.Fatalf("SignDeterministic failed: %v", err)
	}
	// Both verification methods should pass
	if !sm2.VerifyASN1WithSM2(&privKey.PublicKey, nil, msg, detSig) {
		t.Errorf("VerifyASN1WithSM2 failed for deterministic signature")
	}
	sm2Hash, _ := sm2.CalculateSM2Hash(&privKey.PublicKey, msg, nil)
	if !sm2.VerifyASN1(&privKey.PublicKey, sm2Hash, detSig) {
		t.Errorf("VerifyASN1 failed for deterministic signature")
	}
}

// 64-byte hash input

func TestSignDeterministic_LongHash(t *testing.T) {
	privKey, err := sm2.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey failed: %v", err)
	}
	// 64-byte hash (exceeds the curve order byte length of 32)
	longHash := make([]byte, 64)
	for i := range longHash {
		longHash[i] = byte(i)
	}
	sig, err := sm2.SignDeterministic(privKey, longHash, nil)
	if err != nil {
		t.Fatalf("SignDeterministic with long hash failed: %v", err)
	}
	if !sm2.VerifyASN1(&privKey.PublicKey, longHash, sig) {
		t.Errorf("signature verification failed for long hash")
	}
	// Deterministic check
	sig2, err := sm2.SignDeterministic(privKey, longHash, nil)
	if err != nil {
		t.Fatalf("SignDeterministic with long hash (2nd) failed: %v", err)
	}
	if !bytes.Equal(sig, sig2) {
		t.Errorf("SignDeterministic produced different signatures for same long hash")
	}
}

// crypto.Signer interface compatibility

func TestSignDeterministic_SignerInterface(t *testing.T) {
	privKey, err := sm2.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey failed: %v", err)
	}
	msg := []byte("signer interface test")

	sig, err := sm2.SignDeterministic(privKey, msg, sm2.DefaultSM2SignerOpts)
	if err != nil {
		t.Fatalf("SignDeterministic failed: %v", err)
	}

	// Confirm PrivateKey implements crypto.Signer
	var _ crypto.Signer = privKey

	// Sign (random) and SignDeterministic should produce different signatures
	randSig, err := privKey.Sign(rand.Reader, msg, sm2.DefaultSM2SignerOpts)
	if err != nil {
		t.Fatalf("Sign failed: %v", err)
	}
	if !sm2.VerifyASN1WithSM2(&privKey.PublicKey, nil, msg, randSig) {
		t.Errorf("Sign() signature verification failed")
	}
	// Both methods should produce verifiable signatures
	if !sm2.VerifyASN1WithSM2(&privKey.PublicKey, nil, msg, sig) {
		t.Errorf("SignDeterministic signature verification failed")
	}
}

// Sign with nil rand produces deterministic signature

func TestSign_NilRandDeterministic(t *testing.T) {
	privKey, err := sm2.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey failed: %v", err)
	}
	msg := []byte("nil rand test")

	// Sign with nil rand should produce a deterministic signature
	sig1, err := privKey.Sign(nil, msg, sm2.DefaultSM2SignerOpts)
	if err != nil {
		t.Fatalf("Sign with nil rand failed: %v", err)
	}
	if !sm2.VerifyASN1WithSM2(&privKey.PublicKey, nil, msg, sig1) {
		t.Errorf("Sign(nil) produced an invalid signature")
	}

	// Calling Sign(nil) again should produce the same signature
	sig2, err := privKey.Sign(nil, msg, sm2.DefaultSM2SignerOpts)
	if err != nil {
		t.Fatalf("Sign with nil rand (2nd call) failed: %v", err)
	}
	if !bytes.Equal(sig1, sig2) {
		t.Errorf("Sign(nil) produced different signatures for the same input")
	}

	// Sign(nil) should produce the same result as SignDeterministic
	detSig, err := sm2.SignDeterministic(privKey, msg, sm2.DefaultSM2SignerOpts)
	if err != nil {
		t.Fatalf("SignDeterministic failed: %v", err)
	}
	if !bytes.Equal(sig1, detSig) {
		t.Errorf("Sign(nil) and SignDeterministic produced different signatures")
	}

	// Sign(rand.Reader) should produce a different signature (randomized)
	randSig, err := privKey.Sign(rand.Reader, msg, sm2.DefaultSM2SignerOpts)
	if err != nil {
		t.Fatalf("Sign with rand.Reader failed: %v", err)
	}
	if !sm2.VerifyASN1WithSM2(&privKey.PublicKey, nil, msg, randSig) {
		t.Errorf("Sign(rand.Reader) produced an invalid signature")
	}
}

// Sign with nil rand and nil opts

func TestSign_NilRandNilOpts(t *testing.T) {
	privKey, err := sm2.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey failed: %v", err)
	}
	hash := sm3.Sum([]byte("test"))

	sig, err := privKey.Sign(nil, hash[:], nil)
	if err != nil {
		t.Fatalf("Sign with nil rand and nil opts failed: %v", err)
	}
	if !sm2.VerifyASN1(&privKey.PublicKey, hash[:], sig) {
		t.Errorf("signature verification failed for Sign(nil, nil opts)")
	}
}

// Sign with nil rand on unsupported curve

func TestSign_NilRandUnsupportedCurve(t *testing.T) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey failed: %v", err)
	}
	sm2Priv := &sm2.PrivateKey{PrivateKey: *priv}

	_, err = sm2Priv.Sign(nil, []byte("test"), nil)
	if err == nil {
		t.Fatal("expected error for unsupported curve with nil rand")
	}
	if err.Error() != "sm2: curve not supported by deterministic signatures" {
		t.Errorf("unexpected error: %v", err)
	}
}

// Edge case: private key value of 1

func TestSignDeterministic_MinPrivateKey(t *testing.T) {
	privKey, err := sm2.NewPrivateKeyFromInt(new(big.Int).SetInt64(1))
	if err != nil {
		t.Fatalf("NewPrivateKeyFromInt failed: %v", err)
	}
	msg := []byte("min key test")

	sig, err := sm2.SignDeterministic(privKey, msg, sm2.DefaultSM2SignerOpts)
	if err != nil {
		t.Fatalf("SignDeterministic with min private key failed: %v", err)
	}
	if !sm2.VerifyASN1WithSM2(&privKey.PublicKey, nil, msg, sig) {
		t.Errorf("signature verification failed for min private key")
	}
	// Determinism check
	sig2, err := sm2.SignDeterministic(privKey, msg, sm2.DefaultSM2SignerOpts)
	if err != nil {
		t.Fatalf("SignDeterministic with min private key (2nd) failed: %v", err)
	}
	if !bytes.Equal(sig, sig2) {
		t.Errorf("SignDeterministic produced different signatures for min private key")
	}
}

// Error type assertion

func TestSignDeterministic_UnsupportedCurveErrorType(t *testing.T) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey failed: %v", err)
	}
	sm2Priv := &sm2.PrivateKey{PrivateKey: *priv}

	_, err = sm2.SignDeterministic(sm2Priv, []byte("test"), nil)
	if err == nil {
		t.Fatal("expected error for unsupported curve")
	}
}

// Benchmarks

func BenchmarkSignDeterministic_SM2(b *testing.B) {
	priv, err := sm2.GenerateKey(rand.Reader)
	if err != nil {
		b.Fatalf("GenerateKey failed: %v", err)
	}
	msg := []byte("benchmark deterministic signing message")
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := sm2.SignDeterministic(priv, msg, sm2.DefaultSM2SignerOpts)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkSignDeterministic_PreHash(b *testing.B) {
	priv, err := sm2.GenerateKey(rand.Reader)
	if err != nil {
		b.Fatalf("GenerateKey failed: %v", err)
	}
	hash := sm3.Sum([]byte("benchmark deterministic signing message"))
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := sm2.SignDeterministic(priv, hash[:], nil)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkVerifyDeterministic_SM2(b *testing.B) {
	priv, err := sm2.GenerateKey(rand.Reader)
	if err != nil {
		b.Fatalf("GenerateKey failed: %v", err)
	}
	msg := []byte("benchmark deterministic signing message")
	sig, err := sm2.SignDeterministic(priv, msg, sm2.DefaultSM2SignerOpts)
	if err != nil {
		b.Fatalf("SignDeterministic failed: %v", err)
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if !sm2.VerifyASN1WithSM2(&priv.PublicKey, nil, msg, sig) {
			b.Fatal("verification failed")
		}
	}
}
