// Copyright 2026 Sun Yimin. All rights reserved.
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file.

package sm9

import (
	"bytes"
	"encoding/hex"
	"errors"
	"fmt"
	"testing"

	"github.com/emmansun/gmsm/internal/cryptotest/vectors"
)

// TestSemanticsVectors replays the committed SM9 vectors: the GB/T 32918.5
// signature and encryption examples, single-field mutations of them, and the
// key parser edges. Malformed input must produce an error or a false result,
// never a panic.
func TestSemanticsVectors(t *testing.T) {
	suite, err := vectors.Load("sm9_semantics.json")
	if err != nil {
		t.Fatal(err)
	}
	t.Run("SM9SignatureVerify", func(t *testing.T) { testSignatureVectors(t, suite) })
	t.Run("SM9Decrypt", func(t *testing.T) { testDecryptVectors(t, suite) })
	t.Run("SM9SignMasterPublicKey", func(t *testing.T) {
		testKeyParserVectors(t, suite, "SM9SignMasterPublicKey", func(b []byte) error {
			_, err := UnmarshalSignMasterPublicKeyRaw(b)
			return err
		})
	})
	t.Run("SM9EncryptMasterPublicKey", func(t *testing.T) {
		testKeyParserVectors(t, suite, "SM9EncryptMasterPublicKey", func(b []byte) error {
			_, err := UnmarshalEncryptMasterPublicKeyRaw(b)
			return err
		})
	})
	t.Run("SM9SignPrivateKey", func(t *testing.T) {
		testKeyParserVectors(t, suite, "SM9SignPrivateKey", func(b []byte) error {
			_, err := UnmarshalSignPrivateKeyRaw(b)
			return err
		})
	})
	t.Run("SM9EncryptPrivateKey", func(t *testing.T) {
		testKeyParserVectors(t, suite, "SM9EncryptPrivateKey", func(b []byte) error {
			_, err := UnmarshalEncryptPrivateKeyRaw(b)
			return err
		})
	})
	t.Run("SM9SignMasterPrivateKey", func(t *testing.T) {
		testKeyParserVectors(t, suite, "SM9SignMasterPrivateKey", func(b []byte) error {
			_, err := UnmarshalSignMasterPrivateKeyASN1(b)
			return err
		})
	})
	t.Run("SM9EncryptMasterPrivateKey", func(t *testing.T) {
		testKeyParserVectors(t, suite, "SM9EncryptMasterPrivateKey", func(b []byte) error {
			_, err := UnmarshalEncryptMasterPrivateKeyASN1(b)
			return err
		})
	})
	t.Run("SM9ASN1KeyParse", func(t *testing.T) { testASN1ParseVectors(t, suite) })
}

func testSignatureVectors(t *testing.T, suite *vectors.Suite) {
	group, err := suite.Group("SM9SignatureVerify")
	if err != nil {
		t.Fatal(err)
	}
	pub, err := UnmarshalSignMasterPublicKeyRaw(semanticsHex(t, "pub", group.Tests[0].Pub))
	if err != nil {
		t.Fatalf("parsing the vector master public key: %v", err)
	}
	for _, tc := range group.Tests {
		t.Run(fmt.Sprintf("tc%d", tc.TCID), func(t *testing.T) {
			uid := semanticsHex(t, "uid", tc.UID)
			hash := semanticsHex(t, "msg", tc.Msg)
			sig := semanticsHex(t, "sig", tc.Sig)
			got := semanticsCall(t, tc, func() bool {
				return VerifyASN1(pub, uid, byte(tc.HID), hash, sig)
			})
			if want := tc.Result == "valid"; got != want {
				t.Errorf("VerifyASN1() = %v, want %v: %s", got, want, tc.Comment)
			}
		})
	}
}

func testDecryptVectors(t *testing.T, suite *vectors.Suite) {
	group, err := suite.Group("SM9Decrypt")
	if err != nil {
		t.Fatal(err)
	}
	priv, err := UnmarshalEncryptPrivateKeyRaw(semanticsHex(t, "priv", group.Tests[0].Priv))
	if err != nil {
		t.Fatalf("parsing the vector user private key: %v", err)
	}
	for _, tc := range group.Tests {
		t.Run(fmt.Sprintf("tc%d", tc.TCID), func(t *testing.T) {
			if tc.Ordering != "" && tc.Ordering != "C1C3C2" {
				t.Fatalf("unsupported ordering %q", tc.Ordering)
			}
			uid := semanticsHex(t, "uid", tc.UID)
			ciphertext := semanticsHex(t, "ciphertext", tc.Ciphertext)
			var plaintext []byte
			err := semanticsCallErr(t, tc, func() error {
				var err error
				plaintext, err = Decrypt(priv, uid, ciphertext, nil)
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
				if len(ciphertext) >= 64+32+1 && !errors.Is(err, ErrDecryption) {
					t.Fatalf("Decrypt() error = %v, want ErrDecryption", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("Decrypt() error: %v: %s", err, tc.Comment)
			}
			if want := semanticsHex(t, "expected", tc.Expected); !bytes.Equal(plaintext, want) {
				t.Fatalf("Decrypt() = %x, want %x", plaintext, want)
			}
		})
	}
}

// testKeyParserVectors runs one parser over a group. The material lives in
// Pub for public keys and Priv for private keys.
func testKeyParserVectors(t *testing.T, suite *vectors.Suite, groupType string, parse func([]byte) error) {
	group, err := suite.Group(groupType)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range group.Tests {
		t.Run(fmt.Sprintf("tc%d", tc.TCID), func(t *testing.T) {
			material := semanticsHex(t, "key", cmpOr(tc.Pub, tc.Priv))
			err := semanticsCallErr(t, tc, func() error { return parse(material) })
			switch tc.Result {
			case "invalid":
				if err == nil {
					t.Fatalf("parser accepted %x: %s", material, tc.Comment)
				}
			case "valid":
				if err != nil {
					t.Fatalf("parser rejected a valid key: %v: %s", err, tc.Comment)
				}
			default:
				t.Fatalf("unknown result %q", tc.Result)
			}
		})
	}
}

// testASN1ParseVectors feeds each malformed input to every ASN.1 key parser.
func testASN1ParseVectors(t *testing.T, suite *vectors.Suite) {
	group, err := suite.Group("SM9ASN1KeyParse")
	if err != nil {
		t.Fatal(err)
	}
	parsers := []struct {
		name  string
		parse func([]byte) error
	}{
		{"SignMasterPublicKey", func(b []byte) error { _, err := UnmarshalSignMasterPublicKeyASN1(b); return err }},
		{"SignMasterPrivateKey", func(b []byte) error { _, err := UnmarshalSignMasterPrivateKeyASN1(b); return err }},
		{"SignPrivateKey", func(b []byte) error { _, err := UnmarshalSignPrivateKeyASN1(b); return err }},
		{"EncryptMasterPublicKey", func(b []byte) error { _, err := UnmarshalEncryptMasterPublicKeyASN1(b); return err }},
		{"EncryptMasterPrivateKey", func(b []byte) error { _, err := UnmarshalEncryptMasterPrivateKeyASN1(b); return err }},
		{"EncryptPrivateKey", func(b []byte) error { _, err := UnmarshalEncryptPrivateKeyASN1(b); return err }},
	}
	for _, tc := range group.Tests {
		input := semanticsHex(t, "input", tc.Input)
		for _, p := range parsers {
			t.Run(fmt.Sprintf("tc%d/%s", tc.TCID, p.name), func(t *testing.T) {
				err := semanticsCallErr(t, tc, func() error { return p.parse(input) })
				if err == nil {
					t.Fatalf("%s accepted %x: %s", p.name, input, tc.Comment)
				}
			})
		}
	}
}

func cmpOr(a, b string) string {
	if a != "" {
		return a
	}
	return b
}

func semanticsHex(t *testing.T, name, value string) []byte {
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
