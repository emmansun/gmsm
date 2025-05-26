package sm2

import (
	"bufio"
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/hex"
	"io"
	"math/big"
	"testing"

	"github.com/emmansun/gmsm/sm3"
)

func TestParseRawPrivateKey(t *testing.T) {
	c := p256()
	// test nil
	_, err := ParseRawPrivateKey(nil)
	if err == nil || err.Error() != "sm2: invalid private key size" {
		t.Errorf("should throw sm2: invalid private key size")
	}
	// test all zero
	key := make([]byte, c.N.Size())
	_, err = ParseRawPrivateKey(key)
	if err == nil || err != errInvalidPrivateKey {
		t.Errorf("should throw errInvalidPrivateKey")
	}
	// test N-1
	_, err = ParseRawPrivateKey(c.nMinus1.Bytes(c.N))
	if err == nil || err != errInvalidPrivateKey {
		t.Errorf("should throw errInvalidPrivateKey")
	}
	// test N
	_, err = ParseRawPrivateKey(P256().Params().N.Bytes())
	if err == nil || err != errInvalidPrivateKey {
		t.Errorf("should throw errInvalidPrivateKey")
	}
	// test 1
	key[31] = 1
	_, err = ParseRawPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	// test N-2
	_, err = ParseRawPrivateKey(c.nMinus2)
	if err != nil {
		t.Error(err)
	}
}

func TestNewPrivateKeyFromInt(t *testing.T) {
	// test nil
	_, err := NewPrivateKeyFromInt(nil)
	if err == nil || err.Error() != "sm2: private key is nil" {
		t.Errorf("should throw sm2: private key is nil")
	}
	// test 1
	_, err = NewPrivateKeyFromInt(big.NewInt(1))
	if err != nil {
		t.Fatal(err)
	}
	// test N
	_, err = NewPrivateKeyFromInt(P256().Params().N)
	if err == nil || err != errInvalidPrivateKey {
		t.Errorf("should throw errInvalidPrivateKey")
	}

	// test N + 1
	_, err = NewPrivateKeyFromInt(new(big.Int).Add(P256().Params().N, big.NewInt(1)))
	if err == nil || err != errInvalidPrivateKey {
		t.Errorf("should throw errInvalidPrivateKey")
	}

	c := p256()
	// test N - 1
	_, err = NewPrivateKeyFromInt(new(big.Int).SetBytes(c.nMinus1.Bytes(c.N)))
	if err == nil || err != errInvalidPrivateKey {
		t.Errorf("should throw errInvalidPrivateKey")
	}
}

func TestParseUncompressedPublicKey(t *testing.T) {
	// test nil
	_, err := ParseUncompressedPublicKey(nil)
	if err == nil || err.Error() != "sm2: invalid public key" {
		t.Errorf("should throw sm2: invalid public key")
	}
	// test without point format prefix byte
	keypoints, _ := hex.DecodeString("8356e642a40ebd18d29ba3532fbd9f3bbee8f027c3f6f39a5ba2f870369f9988981f5efe55d1c5cdf6c0ef2b070847a14f7fdf4272a8df09c442f3058af94ba1")
	_, err = ParseUncompressedPublicKey(keypoints)
	if err == nil || err.Error() != "sm2: invalid public key" {
		t.Errorf("should throw sm2: invalid public key")
	}
	// test correct point
	keypoints, _ = hex.DecodeString("048356e642a40ebd18d29ba3532fbd9f3bbee8f027c3f6f39a5ba2f870369f9988981f5efe55d1c5cdf6c0ef2b070847a14f7fdf4272a8df09c442f3058af94ba1")
	_, err = ParseUncompressedPublicKey(keypoints)
	if err != nil {
		t.Fatal(err)
	}
	// test point not on curve
	keypoints, _ = hex.DecodeString("048356e642a40ebd18d29ba3532fbd9f3bbee8f027c3f6f39a5ba2f870369f9988981f5efe55d1c5cdf6c0ef2b070847a14f7fdf4272a8df09c442f3058af94ba2")
	_, err = ParseUncompressedPublicKey(keypoints)
	if err == nil || err.Error() != "point not on SM2 P256 curve" {
		t.Errorf("should throw point not on SM2 P256 curve, got %v", err)
	}
}

func testRecoverPublicKeysFromSM2Signature(t *testing.T, priv *PrivateKey) {
	tests := []struct {
		name      string
		plainText string
	}{
		{"less than 32", "encryption standard"},
		{"equals 32", "encryption standard encryption "},
		{"long than 32", "encryption standard encryption standard"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			hashValue, err := CalculateSM2Hash(&priv.PublicKey, []byte(tt.plainText), nil)
			if err != nil {
				t.Fatalf("hash failed %v", err)
			}
			sig, err := priv.Sign(rand.Reader, hashValue, nil)
			if err != nil {
				t.Fatalf("sign failed %v", err)
			}

			pubs, err := RecoverPublicKeysFromSM2Signature(hashValue, sig)
			if err != nil {
				t.Fatalf("recover sig=%x, priv=%x, failed %v", sig, priv.D.Bytes(), err)
			}
			found := false
			for _, pub := range pubs {
				if !VerifyASN1(pub, hashValue, sig) {
					t.Errorf("failed to verify hash for sig=%x, priv=%x", sig, priv.D.Bytes())
				}
				if pub.Equal(&priv.PublicKey) {
					found = true
				}
			}
			if !found {
				t.Errorf("recover failed, not found public key for sig=%x, priv=%x", sig, priv.D.Bytes())
			}
		})
	}
}

func TestRecoverPublicKeysFromSM2Signature(t *testing.T) {
	priv, _ := GenerateKey(rand.Reader)
	testRecoverPublicKeysFromSM2Signature(t, priv)
	keyInt := bigFromHex("d6833540d019e0438a5dd73b414f26ab43d8064b99671206944e284dbd969093")
	priv, _ = NewPrivateKeyFromInt(keyInt)
	testRecoverPublicKeysFromSM2Signature(t, priv)

	// failed case
	hashValue, _ := CalculateSM2Hash(&priv.PublicKey, []byte("encryption standard encryption "), nil)
	signature, _ := hex.DecodeString("3045022000cd0b56bf6be810032d28ff27d6f3468f1f1a09bcf8581f30a5de6692c85ea602210096ba29c086134af1be139dd572f2f2908f30e01fd0c28e06a687cbb0ff6e33ce")
	// verify signature with public key
	if !VerifyASN1(&priv.PublicKey, hashValue, signature) {
		t.Errorf("failed to verify hash for sig=%x, priv=%x", signature, priv.D.Bytes())
	}
	pubs, err := RecoverPublicKeysFromSM2Signature(hashValue, signature)
	if err != nil {
		t.Fatalf("recover failed %v", err)
	}
	found := false
	for _, pub := range pubs {
		if !VerifyASN1(pub, hashValue, signature) {
			t.Errorf("failed to verify hash for sig=%x, priv=%x", signature, priv.D.Bytes())
		}
		if pub.Equal(&priv.PublicKey) {
			found = true
		}
	}
	if !found {
		t.Errorf("recover failed, not found public key for sig=%x, priv=%x", signature, priv.D.Bytes())
	}
}

// Check that signatures remain non-deterministic with a functional entropy source.
func TestINDCCA(t *testing.T) {
	priv, err := GenerateKey(rand.Reader)
	if err != nil {
		t.Errorf("failed to generate key")
	}

	hashed := []byte("testing")
	r0, s0, err := Sign(rand.Reader, &priv.PrivateKey, hashed)
	if err != nil {
		t.Errorf("SM2: error signing: %s", err)
		return
	}

	r1, s1, err := Sign(rand.Reader, &priv.PrivateKey, hashed)
	if err != nil {
		t.Errorf("SM2: error signing: %s", err)
		return
	}

	if s0.Cmp(s1) == 0 {
		t.Error("SM2: two signatures of the same message produced the same result")
	}

	if r0.Cmp(r1) == 0 {
		t.Error("SM2: two signatures of the same message produced the same nonce")
	}
}

func TestNegativeInputs(t *testing.T) {
	key, err := GenerateKey(rand.Reader)
	if err != nil {
		t.Errorf("failed to generate key")
	}

	var hash [32]byte
	r := new(big.Int).SetInt64(1)
	r.Lsh(r, 550 /* larger than any supported curve */)
	r.Neg(r)

	if Verify(&key.PublicKey, hash[:], r, r) {
		t.Errorf("bogus signature accepted")
	}
}

func TestZeroHashSignature(t *testing.T) {
	zeroHash := make([]byte, 64)

	privKey, err := GenerateKey(rand.Reader)
	if err != nil {
		panic(err)
	}

	// Sign a hash consisting of all zeros.
	r, s, err := Sign(rand.Reader, &privKey.PrivateKey, zeroHash)
	if err != nil {
		panic(err)
	}

	// Confirm that it can be verified.
	if !Verify(&privKey.PublicKey, zeroHash, r, s) {
		t.Errorf("zero hash signature verify failed")
	}
}

func TestZeroSignature(t *testing.T) {
	privKey, err := GenerateKey(rand.Reader)
	if err != nil {
		panic(err)
	}
	if Verify(&privKey.PublicKey, make([]byte, 64), big.NewInt(0), big.NewInt(0)) {
		t.Error("Verify with r,s=0 succeeded")
	}
}

func TestNegtativeSignature(t *testing.T) {
	zeroHash := make([]byte, 64)

	privKey, err := GenerateKey(rand.Reader)
	if err != nil {
		panic(err)
	}
	r, s, err := Sign(rand.Reader, &privKey.PrivateKey, zeroHash)
	if err != nil {
		panic(err)
	}

	r = r.Neg(r)
	if Verify(&privKey.PublicKey, zeroHash, r, s) {
		t.Error("Verify with r=-r succeeded")
	}
}

func TestRPlusNSignature(t *testing.T) {
	zeroHash := make([]byte, 64)

	privKey, err := GenerateKey(rand.Reader)
	if err != nil {
		panic(err)
	}
	r, s, err := Sign(rand.Reader, &privKey.PrivateKey, zeroHash)
	if err != nil {
		panic(err)
	}

	r = r.Add(r, P256().Params().N)
	if Verify(&privKey.PublicKey, zeroHash, r, s) {
		t.Error("Verify with r=r+n succeeded")
	}
}

func TestRMinusNSignature(t *testing.T) {
	zeroHash := make([]byte, 64)

	privKey, err := GenerateKey(rand.Reader)
	if err != nil {
		panic(err)
	}
	r, s, err := Sign(rand.Reader, &privKey.PrivateKey, zeroHash)
	if err != nil {
		panic(err)
	}

	r = r.Sub(r, P256().Params().N)
	if Verify(&privKey.PublicKey, zeroHash, r, s) {
		t.Error("Verify with r=r-n succeeded")
	}
}

func TestEqual(t *testing.T) {
	private, _ := GenerateKey(rand.Reader)
	public := &private.PublicKey

	if !public.Equal(public) {
		t.Errorf("public key is not equal to itself: %q", public)
	}
	if !public.Equal(crypto.Signer(private).Public()) {
		t.Errorf("private.Public() is not Equal to public: %q", public)
	}
	if !private.Equal(private) {
		t.Errorf("private key is not equal to itself: %q", private.PrivateKey)
	}

	otherPriv, _ := GenerateKey(rand.Reader)
	otherPub := &otherPriv.PublicKey
	if public.Equal(otherPub) {
		t.Errorf("different public keys are Equal")
	}
	if private.Equal(otherPriv) {
		t.Errorf("different private keys are Equal")
	}
}

func TestPublicKeyToECDH(t *testing.T) {
	priv, _ := GenerateKey(rand.Reader)
	_, err := PublicKeyToECDH(&priv.PublicKey)
	if err != nil {
		t.Fatal(err)
	}

	p256, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	_, err = PublicKeyToECDH(&p256.PublicKey)
	if err == nil {
		t.Fatal("should be error")
	}
}

func TestRandomPoint(t *testing.T) {
	c := p256()
	t.Cleanup(func() { testingOnlyRejectionSamplingLooped = nil })
	var loopCount int
	testingOnlyRejectionSamplingLooped = func() { loopCount++ }

	// A sequence of all ones will generate 2^N-1, which should be rejected.
	// (Unless, for example, we are masking too many bits.)
	r := io.MultiReader(bytes.NewReader(bytes.Repeat([]byte{0xff}, 100)), rand.Reader)
	if k, p, err := randomPoint(c, r, false); err != nil {
		t.Fatal(err)
	} else if k.IsZero() == 1 {
		t.Error("k is zero")
	} else if p.Bytes()[0] != 4 {
		t.Error("p is infinity")
	}
	if loopCount == 0 {
		t.Error("overflow was not rejected")
	}
	loopCount = 0

	// A sequence of all zeroes will generate zero, which should be rejected.
	r = io.MultiReader(bytes.NewReader(bytes.Repeat([]byte{0}, 100)), rand.Reader)
	if k, p, err := randomPoint(c, r, false); err != nil {
		t.Fatal(err)
	} else if k.IsZero() == 1 {
		t.Error("k is zero")
	} else if p.Bytes()[0] != 4 {
		t.Error("p is infinity")
	}
	if loopCount == 0 {
		t.Error("zero was not rejected")
	}
}

func TestPrivateKeyPlus1WithOrderMinus1(t *testing.T) {
	priv := new(PrivateKey)
	priv.D = new(big.Int).Sub(P256().Params().N, big.NewInt(1))
	priv.Curve = P256()
	priv.PublicKey.X, priv.PublicKey.Y = P256().ScalarBaseMult(priv.D.Bytes())

	_, err := priv.inverseOfPrivateKeyPlus1(p256())
	if err == nil || err != errInvalidPrivateKey {
		t.Errorf("expected invalid private key error")
	}
}

func TestSignVerify(t *testing.T) {
	priv, _ := GenerateKey(rand.Reader)
	tests := []struct {
		name      string
		plainText string
	}{
		// TODO: Add test cases.
		{"less than 32", "encryption standard"},
		{"equals 32", "encryption standard encryption "},
		{"long than 32", "encryption standard encryption standard"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			hashed := sm3.Sum([]byte(tt.plainText))
			signature, err := priv.Sign(rand.Reader, hashed[:], nil)
			if err != nil {
				t.Fatalf("sign failed %v", err)
			}
			result := VerifyASN1(&priv.PublicKey, hashed[:], signature)
			if !result {
				t.Fatal("verify failed")
			}
			hashed[0] ^= 0xff
			if VerifyASN1(&priv.PublicKey, hashed[:], signature) {
				t.Errorf("VerifyASN1 always works!")
			}
		})
	}
}

func TestSignMessage(t *testing.T) {
	priv, _ := GenerateKey(rand.Reader)
	tests := []struct {
		name      string
		plainText string
	}{
		// TODO: Add test cases.
		{"less than 32", "encryption standard"},
		{"equals 32", "encryption standard encryption "},
		{"long than 32", "encryption standard encryption standard"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			signature, err := priv.SignMessage(rand.Reader, []byte(tt.plainText), nil)
			if err != nil {
				t.Fatalf("SignMessage failed %v", err)
			}
			result := VerifyASN1WithSM2(&priv.PublicKey, nil, []byte(tt.plainText), signature)
			if !result {
				t.Fatal("verify failed")
			}
			signature, err = priv.SignMessage(rand.Reader, []byte(tt.plainText), NewSM2SignerOption(true, []byte("testid")))
			if err != nil {
				t.Fatalf("SignMessage failed %v", err)
			}
			result = VerifyASN1WithSM2(&priv.PublicKey, []byte("testid"), []byte(tt.plainText), signature)
			if !result {
				t.Fatal("verify failed")
			}
		})
	}
}

func TestSM2Hasher(t *testing.T) {
	tobeHashed := []byte("hello world")
	keypoints, _ := hex.DecodeString("048356e642a40ebd18d29ba3532fbd9f3bbee8f027c3f6f39a5ba2f870369f9988981f5efe55d1c5cdf6c0ef2b070847a14f7fdf4272a8df09c442f3058af94ba1")
	pub, err := NewPublicKey(keypoints)
	if err != nil {
		t.Fatal(err)
	}
	md := sm3.New()
	hasher1, err := NewHash(pub)
	if err != nil {
		t.Fatal(err)
	}
	if hasher1.BlockSize() != md.BlockSize() {
		t.Errorf("expected %d, got %d", md.BlockSize(), hasher1.BlockSize())
	}
	if hasher1.Size() != md.Size() {
		t.Errorf("expected %d, got %d", md.Size(), hasher1.Size())
	}
	hasher1.Write(tobeHashed)
	hash1 := hasher1.Sum(nil)
	expected, err := CalculateSM2Hash(pub, tobeHashed, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(hash1, expected) {
		t.Errorf("expected %x, got %x", expected, hash1)
	}

	hasher2, err := NewHashWithUserID(pub, []byte("john snow"))
	if err != nil {
		t.Fatal(err)
	}
	hasher2.Write(tobeHashed)
	hash2 := hasher2.Sum(nil)
	expected, err = CalculateSM2Hash(pub, tobeHashed, []byte("john snow"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(hash2, expected) {
		t.Errorf("expected %x, got %x", expected, hash2)
	}
}

func TestSM2HasherReset(t *testing.T) {
	tobeHashed := []byte("hello world")
	keypoints, _ := hex.DecodeString("048356e642a40ebd18d29ba3532fbd9f3bbee8f027c3f6f39a5ba2f870369f9988981f5efe55d1c5cdf6c0ef2b070847a14f7fdf4272a8df09c442f3058af94ba1")
	pub, err := NewPublicKey(keypoints)
	if err != nil {
		t.Fatal(err)
	}

	hasher, err := NewHash(pub)
	if err != nil {
		t.Fatal(err)
	}

	hasher.Write(tobeHashed)
	hashBeforeReset := hasher.Sum(nil)

	hasher.Reset()
	hasher.Write(tobeHashed)
	hashAfterReset := hasher.Sum(nil)

	if !bytes.Equal(hashBeforeReset, hashAfterReset) {
		t.Errorf("expected %x, got %x", hashBeforeReset, hashAfterReset)
	}
}

func BenchmarkGenerateKey_SM2(b *testing.B) {
	r := bufio.NewReaderSize(rand.Reader, 1<<15)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := GenerateKey(r); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkSign_SM2(b *testing.B) {
	r := bufio.NewReaderSize(rand.Reader, 1<<15)
	priv, err := GenerateKey(r)
	if err != nil {
		b.Fatal(err)
	}
	hashed := sm3.Sum([]byte("testing"))

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		sig, err := SignASN1(rand.Reader, priv, hashed[:], nil)
		if err != nil {
			b.Fatal(err)
		}
		// Prevent the compiler from optimizing out the operation.
		hashed[0] = sig[0]
	}
}

func BenchmarkSign_SM2Specific(b *testing.B) {
	r := bufio.NewReaderSize(rand.Reader, 1<<15)
	priv, err := GenerateKey(r)
	if err != nil {
		b.Fatal(err)
	}
	hashed := []byte("testingtestingtestingtestingtestingtestingtestingtestingtestingtestingtestingtestingtestingtestingtestingtestingtestingtestingtestingtesting")
	b.RunParallel(func(p *testing.PB) {
		for p.Next() {
			_, err := priv.SignWithSM2(rand.Reader, nil, hashed)
			if err != nil {
				b.Fatal(err)
			}
		}
	})
}

func BenchmarkVerify_SM2(b *testing.B) {
	rd := bufio.NewReaderSize(rand.Reader, 1<<15)
	priv, err := GenerateKey(rd)
	if err != nil {
		b.Fatal(err)
	}
	hashed := []byte("testing")
	r, s, err := Sign(rand.Reader, &priv.PrivateKey, hashed)
	if err != nil {
		b.Fatal(err)
	}

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if !Verify(&priv.PublicKey, hashed, r, s) {
			b.Fatal("verify failed")
		}
	}
}
