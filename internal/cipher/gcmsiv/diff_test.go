// Copyright 2026 Sun Yimin. All rights reserved.
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file.

package cipher

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"encoding/hex"
	"testing"

	"github.com/emmansun/gmsm/internal/byteorder"
	"github.com/emmansun/gmsm/internal/cryptotest/diff"
)

// diffGCMSIVKey16/32 follow the RFC 8452 test-vector key convention
// (0x01 followed by zero bytes) and are pinned constants.
var (
	diffGCMSIVKey16 = []byte{
		0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	}
	diffGCMSIVKey32 = []byte{
		0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	}
)

// TestDiffStandardVector anchors the public GCMSIV dispatch path to RFC 8452
// Appendix C vectors (AES-128 and AES-256) before the differential suites run.
func TestDiffStandardVector(t *testing.T) {
	for _, tc := range []struct {
		name  string
		key   []byte
		plain string
		out   string
	}{
		{"rfc8452-aes128-2", diffGCMSIVKey16, "0100000000000000", "b5d839330ac7b786578782fff6013b815b287c22493a364c"},
		{"rfc8452-aes128-1", diffGCMSIVKey16, "", "dc20e2d83f25705bb49e439eca56de25"},
		{"rfc8452-aes256-28", diffGCMSIVKey32, "01000000000000000000000000000000", "85a01b63025ba19b7fd3ddfc033b3e76c9eac6fa700942702e90862383c6c366"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			plain, err := hex.DecodeString(tc.plain)
			if err != nil {
				t.Fatal(err)
			}
			want, err := hex.DecodeString(tc.out)
			if err != nil {
				t.Fatal(err)
			}
			aead, err := NewGCMSIV(aes.NewCipher, tc.key)
			if err != nil {
				t.Fatal(err)
			}
			nonce, _ := hex.DecodeString("030000000000000000000000")
			got := aead.Seal(nil, nonce, plain, nil)
			if !bytes.Equal(got, want) {
				t.Fatalf("public dispatch does not reproduce the RFC 8452 vector: got %x", got)
			}
		})
	}
}

// diffGCMSIVConcurrent wraps stdlib AES so that deriveMessageKeys and ctrXOR
// route through the concurrent-batch EncryptBlocks paths (Concurrency()=4
// also triggers the second key-derivation batch for 256-bit keys).
type diffGCMSIVConcurrent struct {
	cipher.Block
}

func (b *diffGCMSIVConcurrent) Concurrency() int { return 4 }

func (b *diffGCMSIVConcurrent) EncryptBlocks(dst, src []byte) {
	for i := 0; i < len(src); i += gcmSIVBlockSize {
		b.Block.Encrypt(dst[i:], src[i:])
	}
}

func (b *diffGCMSIVConcurrent) DecryptBlocks(dst, src []byte) {
	for i := 0; i < len(src); i += gcmSIVBlockSize {
		b.Block.Decrypt(dst[i:], src[i:])
	}
}

func newDiffGCMSIVConcurrent(key []byte) (cipher.Block, error) {
	b, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return &diffGCMSIVConcurrent{Block: b}, nil
}

// diffPolyvalRunOf wraps a POLYVAL function into a diff.Run; the tag selects
// the AAD length, the plaintext comes from the case buffer.
func diffPolyvalRunOf(fn func(authKey [16]byte, aad, plaintext []byte, lengthBlock [16]byte) [16]byte) diff.Run[[]byte] {
	return func(t testing.TB, c diff.Case, b *diff.Buffers) []byte {
		var authKey [16]byte
		diff.NewPRNG(c.Seed ^ 0x41555448).Fill(authKey[:])
		aad := make([]byte, int(c.Tag))
		diff.NewPRNG(c.Seed ^ 0x414144).Fill(aad)
		var lengthBlock [16]byte
		byteorder.LEPutUint64(lengthBlock[:8], uint64(len(aad))*8)
		byteorder.LEPutUint64(lengthBlock[8:], uint64(len(b.Src))*8)
		s := fn(authKey, aad, b.Src, lengthBlock)
		return append([]byte(nil), s[:]...)
	}
}

// diffPolyvalAADLens is the AAD length list shared by the domain and the
// fuzz normalize hook; the tag sizes an allocation, so fuzz payloads must
// map it onto this list instead of using the raw value.
var diffPolyvalAADLens = []uint64{0, 1, 16, 17, 33, 64, 127, 128}

func diffPolyvalDomain() diff.Domain {
	return diff.Domain{
		Lengths:    diff.Values(0, 1, 15, 16, 17, 31, 32, 33, 63, 64, 65, 127, 128, 129, 255, 256),
		Tags:       diffPolyvalAADLens, // AAD length
		Alignments: diff.SingleAlignment(),
		Overlaps:   []diff.OverlapCase{diff.NoOverlap()},
		Patterns:   diff.DefaultPatterns(),
		Seeds:      []uint64{0, 1},
	}
}

// TestDiffPolyval checks the accelerated POLYVAL (public dispatch of
// computePolyval) against the forced pure-Go path across padded and unpadded
// AAD/plaintext length combinations.
func TestDiffPolyval(t *testing.T) {
	run := diffPolyvalRunOf(computePolyval)
	s := diff.ByteSuite("generic-polyval", diffPolyvalRefFor(run))
	for _, impl := range diffPolyvalImpls(run) {
		s.Add(impl)
	}
	s.Run(t, diffPolyvalDomain())
}

// FuzzDiffPolyval fuzzes the POLYVAL path. The tag is the AAD length and
// therefore sizes an allocation, so the normalize hook maps it onto the
// declared length list. The reference forces only the pure-Go fallback,
// which is safe regardless of host features.
func FuzzDiffPolyval(f *testing.F) {
	run := diffPolyvalRunOf(computePolyval)
	s := diff.ByteSuite("generic-polyval", diffPolyvalRefFor(run),
		diff.WithNormalize[[]byte](func(c *diff.Case) bool {
			c.Tag = diffPolyvalAADLens[int(c.Tag)%len(diffPolyvalAADLens)]
			return true
		}))
	for _, impl := range diffPolyvalImpls(run) {
		s.Add(impl)
	}
	s.Fuzz(f, diffPolyvalDomain())
}

// diffGCMSIVAADLens are the AAD lengths indexed by tag bits 2 and up.
var diffGCMSIVAADLens = []int{0, 1, 16, 33, 64}

// diffGCMSIVRunOf wraps a block constructor into a diff.Run exercising the
// full AEAD. Tag bit 0 selects the direction (0=seal, 1=seal+open), tag bit 1
// the key size (0=16, 1=32 bytes), the remaining bits index the AAD lengths.
func diffGCMSIVRunOf(newBlock func([]byte) (cipher.Block, error)) diff.Run[[]byte] {
	return func(t testing.TB, c diff.Case, b *diff.Buffers) []byte {
		key := diffGCMSIVKey16
		if c.Tag>>1&1 == 1 {
			key = diffGCMSIVKey32
		}
		aead, err := NewGCMSIV(newBlock, key)
		if err != nil {
			t.Fatalf("failed to construct GCMSIV AEAD: %v", err)
		}
		nonce := make([]byte, gcmSIVNonceSize)
		diff.NewPRNG(c.Seed ^ 0x4E4F4E4345).Fill(nonce)
		aad := make([]byte, diffGCMSIVAADLens[int(c.Tag>>2)%len(diffGCMSIVAADLens)])
		diff.NewPRNG(c.Seed ^ 0x414144).Fill(aad)
		ct := aead.Seal(nil, nonce, b.Src, aad)
		if c.Tag&1 == 0 {
			return ct
		}
		refCT := diffGCMSIVReferenceSeal(func() []byte {
			refAEAD, err := NewGCMSIV(aes.NewCipher, key)
			if err != nil {
				t.Fatal(err)
			}
			return refAEAD.Seal(nil, nonce, b.Src, aad)
		})
		out, err := aead.Open(nil, nonce, refCT, aad)
		if err != nil {
			t.Fatalf("open failed: %v", err)
		}
		return append(ct, out...)
	}
}

func TestDiffGCMSIVOpenComparesCiphertext(t *testing.T) {
	c := diff.Case{SrcLen: 33, DstLen: 49, Overlap: diff.NoOverlap(), Pattern: diff.DeterministicRandom(), Seed: 7, Tag: 6}
	b := diff.Materialize(c)
	run := diffGCMSIVRunOf(aes.NewCipher)
	sealed := run(t, c, b)
	c.Tag |= 1
	opened := run(t, c, b)
	if !bytes.Equal(opened, append(sealed, b.Src...)) {
		t.Fatal("Open differential output must include ciphertext and plaintext")
	}
}

func diffGCMSIVDomain() diff.Domain {
	return diff.Domain{
		Lengths: diff.Values(0, 1, 15, 16, 17, 31, 32, 33, 63, 64, 65,
			127, 128, 129, 255, 256, 511, 512, 1024, 4096),
		Tags:       []uint64{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19}, // aadIdx<<2 | keyIdx<<1 | dir
		Alignments: diff.SingleAlignment(),
		Overlaps:   []diff.OverlapCase{diff.NoOverlap()},
		Patterns:   diff.DefaultPatterns(),
		Seeds:      []uint64{0, 1},
	}
}

// TestDiffGCMSIV checks the public AEAD — with a plain block cipher and with
// a concurrent-batch block cipher (which routes deriveMessageKeys and ctrXOR
// through the EncryptBlocks batching, including the key-256 second batch) —
// against the forced pure-Go POLYVAL path.
func TestDiffGCMSIV(t *testing.T) {
	run := diffGCMSIVRunOf(aes.NewCipher)
	s := diff.ByteSuite("generic-gcmsiv", diffGCMSIVRefFor(run))
	for _, impl := range diffGCMSIVImpls(run) {
		s.Add(impl)
	}
	s.Add(diff.Implementation[[]byte]{
		Name: "aes-concurrent",
		Run:  diffGCMSIVRunOf(newDiffGCMSIVConcurrent),
	})
	s.Run(t, diffGCMSIVDomain())
}

// FuzzDiffGCMSIV fuzzes the full AEAD path.
func FuzzDiffGCMSIV(f *testing.F) {
	run := diffGCMSIVRunOf(aes.NewCipher)
	s := diff.ByteSuite("generic-gcmsiv", diffGCMSIVRefFor(run))
	for _, impl := range diffGCMSIVImpls(run) {
		s.Add(impl)
	}
	s.Add(diff.Implementation[[]byte]{
		Name: "aes-concurrent",
		Run:  diffGCMSIVRunOf(newDiffGCMSIVConcurrent),
	})
	s.Fuzz(f, diffGCMSIVDomain())
}

// TestDispatchSelectedImplementation verifies that the POLYVAL dispatch
// variable is consistent with the host CPU features. CI reruns it in a
// separate go test process with DISABLE_GHASH=1 to cover the other riscv64
// state; the accelerated path is additionally diffed directly whenever it
// is available.
func TestDispatchSelectedImplementation(t *testing.T) {
	checkDispatch(t)
}
