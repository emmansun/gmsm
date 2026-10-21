// Copyright 2026 Sun Yimin. All rights reserved.
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file.

package sm2

import (
	"crypto/ecdsa"
	"encoding/hex"
	"fmt"
	"math/big"
	"testing"

	"github.com/emmansun/gmsm/internal/cryptotest/vectors"
)

// TestSemanticsVectors replays the committed SM2 semantics vectors. Each case
// carries a verdict instead of an output, so a change that starts accepting a
// malformed input, or rejecting a valid one, fails here. A panic counts as a
// failure: malformed input must produce an error or a false result, never a
// crash.
func TestSemanticsVectors(t *testing.T) {
	suite, err := vectors.Load("sm2_semantics.json")
	if err != nil {
		t.Fatal(err)
	}
	t.Run("VerifyDigest", func(t *testing.T) { testVerifyDigestVectors(t, suite) })
	t.Run("VerifySM2", func(t *testing.T) { testVerifySM2Vectors(t, suite) })
}

func testVerifyDigestVectors(t *testing.T, suite *vectors.Suite) {
	group, err := suite.Group("VerifyDigest")
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range group.Tests {
		t.Run(fmt.Sprintf("tc%d", tc.TCID), func(t *testing.T) {
			pub := semanticsPublicKey(t, tc)
			hash := semanticsHex(t, tc, "hash", tc.Hash)
			r := semanticsInt(t, tc, "r", tc.R)
			s := semanticsInt(t, tc, "s", tc.S)
			got := semanticsCall(t, tc, func() bool { return Verify(pub, hash, r, s) })
			if want := tc.Result == "valid"; got != want {
				t.Errorf("Verify() = %v, want %v: %s", got, want, tc.Comment)
			}
		})
	}
}

func testVerifySM2Vectors(t *testing.T, suite *vectors.Suite) {
	group, err := suite.Group("VerifySM2")
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range group.Tests {
		t.Run(fmt.Sprintf("tc%d", tc.TCID), func(t *testing.T) {
			pub := semanticsPublicKey(t, tc)
			uid := semanticsOptionalHex(t, "uid", tc.UID)
			msg := semanticsOptionalHex(t, "msg", tc.Msg)
			sig := semanticsOptionalHex(t, "sig", tc.Sig)
			got := semanticsCall(t, tc, func() bool { return VerifyASN1WithSM2(pub, uid, msg, sig) })
			if want := tc.Result == "valid"; got != want {
				t.Errorf("VerifyASN1WithSM2() = %v, want %v: %s", got, want, tc.Comment)
			}
		})
	}
}

func semanticsPublicKey(t *testing.T, tc vectors.Case) *ecdsa.PublicKey {
	t.Helper()
	pub, err := ParseUncompressedPublicKey(semanticsHex(t, tc, "pub", tc.Pub))
	if err != nil {
		t.Fatalf("parsing the vector public key: %v", err)
	}
	return pub
}

func semanticsHex(t *testing.T, tc vectors.Case, name, value string) []byte {
	t.Helper()
	if value == "" {
		t.Fatalf("%s is required", name)
	}
	return semanticsOptionalHex(t, name, value)
}

func semanticsOptionalHex(t *testing.T, name, value string) []byte {
	t.Helper()
	if value == "" {
		return nil
	}
	data, err := hex.DecodeString(value)
	if err != nil {
		t.Fatalf("%s: %v", name, err)
	}
	return data
}

func semanticsInt(t *testing.T, tc vectors.Case, name, value string) *big.Int {
	t.Helper()
	return new(big.Int).SetBytes(semanticsHex(t, tc, name, value))
}

// semanticsCall runs one vector call and turns a panic into a test failure
// that names the case.
func semanticsCall(t *testing.T, tc vectors.Case, call func() bool) (got bool) {
	t.Helper()
	defer func() {
		if p := recover(); p != nil {
			t.Fatalf("tc%d panicked: %v", tc.TCID, p)
		}
	}()
	return call()
}
