// Copyright 2026 Sun Yimin. All rights reserved.
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file.

package cipher_test

import (
	"bytes"
	stdcipher "crypto/cipher"
	"encoding/binary"
	"fmt"
	"testing"

	"github.com/emmansun/gmsm/cipher"
	"github.com/emmansun/gmsm/internal/cryptotest/vectors"
	"github.com/emmansun/gmsm/sm4"
)

// TestAEADVectors replays the committed SM4 AEAD and XTS vectors. Every valid
// case must both seal to the recorded ciphertext and open back to the recorded
// plaintext; every invalid case must be rejected by the constructor or by
// Open, never by a panic.
func TestAEADVectors(t *testing.T) {
	suite, err := vectors.Load("sm4_aead.json")
	if err != nil {
		t.Fatal(err)
	}
	t.Run("GCM", func(t *testing.T) { testGCMVectors(t, suite) })
	t.Run("CCM", func(t *testing.T) { testCCMVectors(t, suite) })
	t.Run("GCMSIV", func(t *testing.T) { testGCMSIVVectors(t, suite) })
	t.Run("XTS", func(t *testing.T) { testXTSVectors(t, suite, "XTS", false) })
	t.Run("GBXTS", func(t *testing.T) { testXTSVectors(t, suite, "GBXTS", true) })
}

func testGCMVectors(t *testing.T, suite *vectors.Suite) {
	group, err := suite.Group("GCM")
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range group.Tests {
		t.Run(fmt.Sprintf("tc%d", tc.TCID), func(t *testing.T) {
			key := mustDecodeHex(t, tc.Key)
			nonce := mustDecodeHex(t, tc.Nonce)
			aad := mustDecodeHex(t, tc.AAD)
			plaintext := mustDecodeHex(t, tc.Plaintext)
			ciphertext := mustDecodeHex(t, tc.Ciphertext)

			nonceSize := tc.NonceSize
			if nonceSize == 0 {
				nonceSize = 12
			}
			if nonceSize != len(nonce) {
				t.Fatalf("vector error: nonceSize is %d but the nonce has %d bytes", nonceSize, len(nonce))
			}
			if tc.TagSize != 0 && nonceSize != 12 {
				t.Fatalf("vector error: tag size %d cannot be combined with a %d-byte nonce", tc.TagSize, nonceSize)
			}

			block, err := sm4.NewCipher(key)
			if err != nil {
				reportAEADSetupFailure(t, tc, err)
				return
			}
			var aead stdcipher.AEAD
			switch {
			case tc.TagSize != 0:
				aead, err = stdcipher.NewGCMWithTagSize(block, tc.TagSize)
			case nonceSize != 12:
				aead, err = stdcipher.NewGCMWithNonceSize(block, nonceSize)
			default:
				aead, err = stdcipher.NewGCM(block)
			}
			if err != nil {
				reportAEADSetupFailure(t, tc, err)
				return
			}
			checkAEAD(t, tc, aead, nonce, plaintext, ciphertext, aad)
		})
	}
}

func testCCMVectors(t *testing.T, suite *vectors.Suite) {
	group, err := suite.Group("CCM")
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range group.Tests {
		t.Run(fmt.Sprintf("tc%d", tc.TCID), func(t *testing.T) {
			key := mustDecodeHex(t, tc.Key)
			nonce := mustDecodeHex(t, tc.Nonce)
			aad := mustDecodeHex(t, tc.AAD)
			plaintext := mustDecodeHex(t, tc.Plaintext)
			ciphertext := mustDecodeHex(t, tc.Ciphertext)

			nonceSize := tc.NonceSize
			if nonceSize == 0 {
				nonceSize = len(nonce)
			}
			tagSize := tc.TagSize
			if tagSize == 0 {
				tagSize = 16
			}

			block, err := sm4.NewCipher(key)
			if err != nil {
				reportAEADSetupFailure(t, tc, err)
				return
			}
			aead, err := cipher.NewCCMWithNonceAndTagSize(block, nonceSize, tagSize)
			if err != nil {
				reportAEADSetupFailure(t, tc, err)
				return
			}
			if nonceSize != len(nonce) {
				t.Fatalf("vector error: nonceSize is %d but the nonce has %d bytes", nonceSize, len(nonce))
			}
			checkAEAD(t, tc, aead, nonce, plaintext, ciphertext, aad)
		})
	}
}

func testGCMSIVVectors(t *testing.T, suite *vectors.Suite) {
	group, err := suite.Group("GCMSIV")
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range group.Tests {
		t.Run(fmt.Sprintf("tc%d", tc.TCID), func(t *testing.T) {
			key := mustDecodeHex(t, tc.Key)
			nonce := mustDecodeHex(t, tc.Nonce)
			aad := mustDecodeHex(t, tc.AAD)
			plaintext := mustDecodeHex(t, tc.Plaintext)
			ciphertext := mustDecodeHex(t, tc.Ciphertext)

			aead, err := cipher.NewGCMSIV(sm4.NewCipher, key)
			if err != nil {
				reportAEADSetupFailure(t, tc, err)
				return
			}
			checkAEAD(t, tc, aead, nonce, plaintext, ciphertext, aad)
		})
	}
}

func testXTSVectors(t *testing.T, suite *vectors.Suite, groupType string, gb bool) {
	group, err := suite.Group(groupType)
	if err != nil {
		t.Fatal(err)
	}
	newEncrypter, newDecrypter := cipher.NewXTSEncrypter, cipher.NewXTSDecrypter
	if gb {
		newEncrypter, newDecrypter = cipher.NewGBXTSEncrypter, cipher.NewGBXTSDecrypter
	}
	for _, tc := range group.Tests {
		t.Run(fmt.Sprintf("tc%d", tc.TCID), func(t *testing.T) {
			key := mustDecodeHex(t, tc.Key)
			tweakKey := mustDecodeHex(t, tc.Key2)
			plaintext := mustDecodeHex(t, tc.Plaintext)
			ciphertext := mustDecodeHex(t, tc.Ciphertext)
			tweak := mustDecodeHex(t, tc.Tweak)
			if len(tweak) == 0 {
				tweak = make([]byte, 16)
				binary.LittleEndian.PutUint64(tweak, tc.Sector)
			}

			encrypter, err := newEncrypter(sm4.NewCipher, key, tweakKey, tweak)
			if err != nil {
				reportAEADSetupFailure(t, tc, err)
				return
			}
			decrypter, err := newDecrypter(sm4.NewCipher, key, tweakKey, tweak)
			if err != nil {
				t.Fatalf("decrypter rejected a case the encrypter accepted: %v", err)
			}
			if tc.Result == "invalid" {
				t.Fatalf("constructor accepted an invalid vector: %s", tc.Comment)
			}

			sealed := make([]byte, len(plaintext))
			encrypter.CryptBlocks(sealed, plaintext)
			if !bytes.Equal(sealed, ciphertext) {
				t.Fatalf("CryptBlocks() = %x, want %x", sealed, ciphertext)
			}
			opened := make([]byte, len(ciphertext))
			decrypter.CryptBlocks(opened, ciphertext)
			if !bytes.Equal(opened, plaintext) {
				t.Fatalf("decrypted = %x, want %x", opened, plaintext)
			}
		})
	}
}

// reportAEADSetupFailure fails a valid case and ignores an invalid one, which
// is expected to be rejected before any data is processed.
func reportAEADSetupFailure(t *testing.T, tc vectors.Case, err error) {
	t.Helper()
	if tc.Result == "valid" {
		t.Fatalf("rejected a valid vector: %v", err)
	}
}

// checkAEAD verifies the seal/open contract of a constructed AEAD. A panic on
// malformed input counts as a failure: the API must return an error.
func checkAEAD(t *testing.T, tc vectors.Case, aead stdcipher.AEAD, nonce, plaintext, ciphertext, aad []byte) {
	t.Helper()
	defer func() {
		if p := recover(); p != nil {
			t.Fatalf("panicked: %v", p)
		}
	}()

	if tc.Result == "invalid" {
		if _, err := aead.Open(nil, nonce, ciphertext, aad); err == nil {
			t.Fatalf("Open accepted an invalid vector: %s", tc.Comment)
		}
		return
	}

	sealed := aead.Seal(nil, nonce, plaintext, aad)
	if !bytes.Equal(sealed, ciphertext) {
		t.Fatalf("Seal() = %x, want %x", sealed, ciphertext)
	}
	opened, err := aead.Open(nil, nonce, ciphertext, aad)
	if err != nil {
		t.Fatalf("Open() failed: %v", err)
	}
	if !bytes.Equal(opened, plaintext) {
		t.Fatalf("Open() = %x, want %x", opened, plaintext)
	}
}
