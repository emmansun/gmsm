// Copyright 2026 Sun Yimin. All rights reserved.
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file.

// Package sm2vectors builds the committed SM2 semantics vectors.
//
// Expected verdicts come from the GB/T 32918 equations, not from the library
// under test. A positive signature is constructed from a fixed nonce k with
// r = e + x1 mod n and s = (1 + d)^-1 (k - r d) mod n, and every case is
// re-checked against the verification equation r == e + x(sG + (r+s)P) mod n
// before it is written out. The group law itself is pinned by the
// differential and kernel suites, so the only thing this package has to get
// right is the equation wiring, which is what the vectors exist to catch.
package sm2vectors

import (
	"crypto/elliptic"
	"encoding/asn1"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"

	"github.com/emmansun/gmsm/internal/cryptotest/vectors"
	"github.com/emmansun/gmsm/sm2"
	"github.com/emmansun/gmsm/sm3"
)

const vectorName = "sm2_semantics.json"

// SuiteFileName returns the committed file name of the suite.
func SuiteFileName() string { return vectorName }

// defaultUID is the default user identifier fixed by GM/T 0009-2023. It is
// repeated here so that the empty-uid case can compute ZA without calling
// the code under test.
var defaultUID = []byte("1234567812345678")

// The private keys are fixed scalars below the group order. With d = 1 the
// public key is the base point G, so those cases can be checked against the
// specification by hand.
var (
	keyOne   = big.NewInt(1)
	keyFixed = mustHexInt("3945208f7b2144b13f36e38ac6d39f95889393692860b51a42fb81ef4df7c5b8")

	// midNonce is an arbitrary nonce away from the 1 and n-1 boundaries.
	midNonce = mustHexInt("0f1e2d3c4b5a69788796a5b4c3d2e1f00f1e2d3c4b5a69788796a5b4c3d2e1f0")
)

func curve() elliptic.Curve { return sm2.P256() }

func mustHexInt(s string) *big.Int {
	v, ok := new(big.Int).SetString(s, 16)
	if !ok {
		panic("sm2vectors: invalid hex constant " + s)
	}
	return v
}

// fixed32 encodes v as a 32-byte big-endian integer, the width of every SM2
// field element.
func fixed32(v *big.Int) []byte {
	return v.FillBytes(make([]byte, 32))
}

func sm3Sum(s string) []byte {
	sum := sm3.Sum([]byte(s))
	return sum[:]
}

// signer is a key pair together with its SEC 1 encoding.
type signer struct {
	d      *big.Int
	px, py *big.Int
	pub    string
}

func newSigner(d *big.Int) *signer {
	x, y := curve().ScalarBaseMult(d.Bytes())
	return &signer{
		d:   d,
		px:  x,
		py:  y,
		pub: hex.EncodeToString(elliptic.Marshal(curve(), x, y)),
	}
}

// signature derives (r, s) for digest e with nonce k using the GB/T 32918.2
// signing equations.
func (s *signer) signature(k, e *big.Int) (*big.Int, *big.Int, error) {
	n := curve().Params().N
	x1, _ := curve().ScalarBaseMult(k.Bytes())
	r := new(big.Int).Add(e, x1)
	r.Mod(r, n)
	if r.Sign() == 0 {
		return nil, nil, fmt.Errorf("degenerate nonce: r is zero")
	}
	rd := new(big.Int).Mul(r, s.d)
	rd.Mod(rd, n)
	num := new(big.Int).Sub(k, rd)
	num.Mod(num, n)
	den := new(big.Int).Add(s.d, big.NewInt(1))
	den.ModInverse(den, n)
	sig := new(big.Int).Mul(num, den)
	sig.Mod(sig, n)
	if sig.Sign() == 0 {
		return nil, nil, fmt.Errorf("degenerate nonce: s is zero")
	}
	return r, sig, nil
}

// verifyEquation evaluates the GB/T 32918.2 verification equation directly,
// including the range and zero checks that make r = 0, s = 0 and t = 0
// invalid.
func verifyEquation(px, py, e, r, s *big.Int) bool {
	n := curve().Params().N
	if r.Sign() <= 0 || r.Cmp(n) >= 0 || s.Sign() <= 0 || s.Cmp(n) >= 0 {
		return false
	}
	t := new(big.Int).Add(r, s)
	t.Mod(t, n)
	if t.Sign() == 0 {
		return false
	}
	sx, sy := curve().ScalarBaseMult(s.Bytes())
	tx, ty := curve().ScalarMult(px, py, t.Bytes())
	x, y := curve().Add(sx, sy, tx, ty)
	if x.Sign() == 0 && y.Sign() == 0 {
		return false
	}
	sum := new(big.Int).Add(e, x)
	sum.Mod(sum, n)
	return sum.Cmp(r) == 0
}

// digest computes e = SM3(ZA || msg) per GB/T 32918.2. An empty uid means the
// default user identifier.
func (s *signer) digest(uid, msg []byte) *big.Int {
	if len(uid) == 0 {
		uid = defaultUID
	}
	params := curve().Params()
	a := new(big.Int).Sub(params.P, big.NewInt(3))
	za := make([]byte, 0, 2+len(uid)+6*32)
	bitLen := len(uid) * 8
	za = append(za, byte(bitLen>>8), byte(bitLen))
	za = append(za, uid...)
	for _, v := range []*big.Int{a, params.B, params.Gx, params.Gy, s.px, s.py} {
		za = append(za, fixed32(v)...)
	}
	zaHash := sm3.Sum(za)
	sum := sm3.Sum(append(zaHash[:], msg...))
	return new(big.Int).SetBytes(sum[:])
}

func verdict(valid bool) string {
	if valid {
		return "valid"
	}
	return "invalid"
}

// digestCase emits a VerifyDigest case; the consumer calls
// Verify(pub, hash, r, s).
func (s *signer) digestCase(tcID int, comment string, e, r, sig *big.Int, valid bool) (vectors.Case, error) {
	if got := verifyEquation(s.px, s.py, e, r, sig); got != valid {
		return vectors.Case{}, fmt.Errorf("VerifyDigest tc%d: equation = %v, want %v", tcID, got, valid)
	}
	return vectors.Case{
		TCID:    tcID,
		Comment: comment,
		Pub:     s.pub,
		Hash:    hex.EncodeToString(fixed32(e)),
		R:       hex.EncodeToString(fixed32(r)),
		S:       hex.EncodeToString(fixed32(sig)),
		Result:  verdict(valid),
	}, nil
}

// sm2Case emits a VerifySM2 case; the consumer calls
// VerifyASN1WithSM2(pub, uid, msg, sig) and recomputes e from uid and msg.
func (s *signer) sm2Case(tcID int, comment string, uid, msg []byte, r, sig *big.Int, valid bool) (vectors.Case, error) {
	e := s.digest(uid, msg)
	if got := verifyEquation(s.px, s.py, e, r, sig); got != valid {
		return vectors.Case{}, fmt.Errorf("VerifySM2 tc%d: equation = %v, want %v", tcID, got, valid)
	}
	return vectors.Case{
		TCID:    tcID,
		Comment: comment,
		Pub:     s.pub,
		UID:     hex.EncodeToString(uid),
		Msg:     hex.EncodeToString(msg),
		Sig:     hex.EncodeToString(encodeSignature(r, sig)),
		Result:  verdict(valid),
	}, nil
}

// malformedCase emits a VerifySM2 case whose signature bytes are deliberately
// not a valid DER encoding. No equation applies: the verdict is decided by
// the parser.
func (s *signer) malformedCase(tcID int, comment string, uid, msg, sig []byte) vectors.Case {
	return vectors.Case{
		TCID:    tcID,
		Comment: comment,
		Pub:     s.pub,
		UID:     hex.EncodeToString(uid),
		Msg:     hex.EncodeToString(msg),
		Sig:     hex.EncodeToString(sig),
		Result:  "invalid",
	}
}

func encodeSignature(r, s *big.Int) []byte {
	der, err := asn1.Marshal(struct{ R, S *big.Int }{r, s})
	if err != nil {
		panic("sm2vectors: encoding signature: " + err.Error())
	}
	return der
}

func buildVerifyDigest() ([]vectors.Case, error) {
	n := curve().Params().N
	one := newSigner(keyOne)
	fixed := newSigner(keyFixed)

	e1 := new(big.Int).SetBytes(sm3Sum("gmsm sm2 verify digest"))
	e2 := new(big.Int).SetBytes(sm3Sum("gmsm sm2 verify digest, second message"))

	r1, s1, err := one.signature(big.NewInt(1), e1)
	if err != nil {
		return nil, err
	}
	r2, s2, err := one.signature(new(big.Int).Sub(n, big.NewInt(1)), e1)
	if err != nil {
		return nil, err
	}
	r3, s3, err := fixed.signature(midNonce, e2)
	if err != nil {
		return nil, err
	}
	r4, s4, err := fixed.signature(big.NewInt(3), e2)
	if err != nil {
		return nil, err
	}

	zero := new(big.Int)
	oneInt := big.NewInt(1)
	flipped := new(big.Int).Xor(e1, big.NewInt(1))
	nMinus1 := new(big.Int).Sub(n, big.NewInt(1))
	nPlus1 := new(big.Int).Add(n, big.NewInt(1))
	malleable := new(big.Int).Sub(n, r1)

	var (
		cases []vectors.Case
		fail  error
	)
	add := func(c vectors.Case, err error) {
		if err != nil {
			if fail == nil {
				fail = err
			}
			return
		}
		cases = append(cases, c)
	}

	add(one.digestCase(1, "base-point key, nonce 1", e1, r1, s1, true))
	add(one.digestCase(2, "base-point key, nonce n-1", e1, r2, s2, true))
	add(fixed.digestCase(3, "fixed key, mid-range nonce", e2, r3, s3, true))
	add(fixed.digestCase(4, "fixed key, nonce 3", e2, r4, s4, true))

	add(one.digestCase(5, "digest altered in the low bit", flipped, r1, s1, false))
	add(one.digestCase(6, "r is zero", e1, zero, s1, false))
	add(one.digestCase(7, "s is zero", e1, r1, zero, false))
	add(one.digestCase(8, "r equals the group order", e1, n, s1, false))
	add(one.digestCase(9, "s equals the group order", e1, r1, n, false))
	add(one.digestCase(10, "r exceeds the group order", e1, nPlus1, s1, false))
	add(one.digestCase(11, "s exceeds the group order", e1, r1, nPlus1, false))
	add(one.digestCase(12, "s is n-r", e1, r1, malleable, false))
	add(one.digestCase(13, "r and s are one", e1, oneInt, oneInt, false))
	add(one.digestCase(14, "r and s swapped", e1, s1, r1, false))
	add(fixed.digestCase(15, "signature from a different key", e1, r1, s1, false))
	add(one.digestCase(16, "r and s are n-1", e1, nMinus1, nMinus1, false))

	if fail != nil {
		return nil, fail
	}
	return cases, nil
}

func buildVerifySM2() ([]vectors.Case, error) {
	one := newSigner(keyOne)
	fixed := newSigner(keyFixed)

	msg := []byte("gmsm sm2 semantics vector")
	otherMsg := []byte("gmsm sm2 semantics vector!")
	customUID := []byte("alice@example.com")
	otherUID := []byte("bob@example.com")

	r1, s1, err := one.signature(big.NewInt(1), one.digest(nil, msg))
	if err != nil {
		return nil, err
	}
	r2, s2, err := fixed.signature(midNonce, fixed.digest(customUID, msg))
	if err != nil {
		return nil, err
	}
	r3, s3, err := one.signature(big.NewInt(2), one.digest(customUID, nil))
	if err != nil {
		return nil, err
	}

	der := encodeSignature(r2, s2)
	if len(der) < 3 || der[1] == 0 || der[1] >= 0x80 {
		return nil, fmt.Errorf("unexpected DER length encoding: %x", der)
	}
	truncated := der[:len(der)-1]
	trailing := append(append([]byte(nil), der...), 0x00)
	shortLen := append([]byte(nil), der...)
	shortLen[1]--

	var (
		cases []vectors.Case
		fail  error
	)
	add := func(c vectors.Case, err error) {
		if err != nil {
			if fail == nil {
				fail = err
			}
			return
		}
		cases = append(cases, c)
	}

	add(one.sm2Case(1, "default uid, empty uid field", nil, msg, r1, s1, true))
	add(one.sm2Case(2, "default uid written out explicitly", defaultUID, msg, r1, s1, true))
	add(fixed.sm2Case(3, "custom uid", customUID, msg, r2, s2, true))
	add(one.sm2Case(4, "custom uid, empty message", customUID, nil, r3, s3, true))

	add(fixed.sm2Case(5, "wrong uid", otherUID, msg, r2, s2, false))
	add(fixed.sm2Case(6, "altered message", customUID, otherMsg, r2, s2, false))
	add(fixed.sm2Case(7, "signature from a different key", customUID, msg, r1, s1, false))

	cases = append(cases,
		fixed.malformedCase(8, "signature truncated by one byte", customUID, msg, truncated),
		fixed.malformedCase(9, "trailing byte after the sequence", customUID, msg, trailing),
		fixed.malformedCase(10, "sequence length one byte short", customUID, msg, shortLen),
		fixed.malformedCase(11, "empty signature", customUID, msg, nil),
	)

	if fail != nil {
		return nil, fail
	}
	return cases, nil
}

// BuildSuite builds the SM2 semantics suite. The output is deterministic;
// TestVectorsUpToDate regenerates it and compares it with the committed file.
func BuildSuite() (*vectors.Suite, error) {
	digest, err := buildVerifyDigest()
	if err != nil {
		return nil, err
	}
	withZA, err := buildVerifySM2()
	if err != nil {
		return nil, err
	}
	suite := &vectors.Suite{
		Schema:    vectors.SemanticsSchema,
		Algorithm: "sm2p256v1",
		Generator: "go test ./internal/cryptotest/sm2vectors -run TestVectorsUpToDate -update",
		Groups: []vectors.Group{
			{
				Type:    "VerifyDigest",
				Comment: "sm2.Verify(pub, hash, r, s). Signatures are derived from the GB/T 32918.2 equations with a fixed nonce and re-checked against the verification equation, so every verdict is independent of the code under test.",
				Tests:   digest,
			},
			{
				Type:    "VerifySM2",
				Comment: "sm2.VerifyASN1WithSM2(pub, uid, msg, sig). e is recomputed from ZA and msg; an empty uid means the GM/T 0009 default identifier.",
				Tests:   withZA,
			},
		},
	}
	if err := suite.Validate(); err != nil {
		return nil, err
	}
	return suite, nil
}

// MarshalSuite renders the suite exactly as it is committed.
func MarshalSuite(s *vectors.Suite) ([]byte, error) {
	data, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(data, '\n'), nil
}
