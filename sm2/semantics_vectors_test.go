// Copyright 2026 Sun Yimin. All rights reserved.
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file.

package sm2

import (
	"bytes"
	"crypto/ecdsa"
	"encoding/hex"
	"errors"
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
	t.Run("PublicKeyDecode", func(t *testing.T) { testPublicKeyDecodeVectors(t, suite) })
	t.Run("PkeDecrypt", func(t *testing.T) { testPkeDecryptVectors(t, suite) })
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

func testPublicKeyDecodeVectors(t *testing.T, suite *vectors.Suite) {
	group, err := suite.Group("PublicKeyDecode")
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range group.Tests {
		t.Run(fmt.Sprintf("tc%d", tc.TCID), func(t *testing.T) {
			data := semanticsHex(t, tc, "pub", tc.Pub)
			var pub *ecdsa.PublicKey
			err := semanticsCallErr(t, tc, func() error {
				var err error
				pub, err = ParseUncompressedPublicKey(data)
				return err
			})
			if tc.Result == "invalid" {
				if err == nil {
					t.Fatalf("ParseUncompressedPublicKey() = (%x, %x), want an error: %s", pub.X, pub.Y, tc.Comment)
				}
				if pub != nil {
					t.Fatalf("ParseUncompressedPublicKey() returned a key along with %v", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("ParseUncompressedPublicKey() error: %v: %s", err, tc.Comment)
			}
			wantX := semanticsInt(t, tc, "x", tc.X)
			wantY := semanticsInt(t, tc, "y", tc.Y)
			if pub.X.Cmp(wantX) != 0 || pub.Y.Cmp(wantY) != 0 {
				t.Fatalf("ParseUncompressedPublicKey() = (%x, %x), want (%x, %x)", pub.X, pub.Y, wantX, wantY)
			}
		})
	}
}

func testPkeDecryptVectors(t *testing.T, suite *vectors.Suite) {
	group, err := suite.Group("PkeDecrypt")
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range group.Tests {
		t.Run(fmt.Sprintf("tc%d", tc.TCID), func(t *testing.T) {
			priv := semanticsPrivateKey(t, tc)
			ct := semanticsOptionalHex(t, "ciphertext", tc.Ciphertext)
			var plaintext []byte
			err := semanticsCallErr(t, tc, func() error {
				var err error
				switch tc.Ordering {
				case "", "C1C3C2":
					plaintext, err = Decrypt(priv, ct)
				case "C1C2C3":
					plaintext, err = priv.Decrypt(nil, ct, NewPlainDecrypterOpts(C1C2C3))
				case "ASN1":
					plaintext, err = priv.Decrypt(nil, ct, ASN1DecrypterOpts)
				default:
					t.Fatalf("unknown ordering %q", tc.Ordering)
				}
				return err
			})
			if tc.Result == "invalid" {
				if err == nil {
					t.Fatalf("Decrypt() = %x, want an error: %s", plaintext, tc.Comment)
				}
				if len(plaintext) != 0 {
					t.Fatalf("Decrypt() returned %x along with %v", plaintext, err)
				}
				// Everything past the initial length check must collapse into
				// ErrDecryption, so callers cannot tell the failure apart.
				if len(ct) > 65 && !errors.Is(err, ErrDecryption) {
					t.Fatalf("Decrypt() error = %v, want ErrDecryption", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("Decrypt() error: %v: %s", err, tc.Comment)
			}
			if want := semanticsHex(t, tc, "expected", tc.Expected); !bytes.Equal(plaintext, want) {
				t.Fatalf("Decrypt() = %x, want %x", plaintext, want)
			}
		})
	}
}

func semanticsPrivateKey(t *testing.T, tc vectors.Case) *PrivateKey {
	t.Helper()
	d := semanticsInt(t, tc, "priv", tc.Priv)
	priv := new(PrivateKey)
	priv.D = d
	priv.Curve = P256()
	priv.X, priv.Y = priv.ScalarBaseMult(d.Bytes())
	return priv
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

// semanticsCallErr runs one vector call that reports an error and turns a
// panic into a test failure that names the case.
func semanticsCallErr(t *testing.T, tc vectors.Case, call func() error) (err error) {
	t.Helper()
	defer func() {
		if p := recover(); p != nil {
			t.Fatalf("tc%d panicked: %v", tc.TCID, p)
		}
	}()
	return call()
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
