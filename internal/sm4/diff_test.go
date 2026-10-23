// Copyright 2026 Sun Yimin. All rights reserved.
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file.

package sm4

import (
	"bytes"
	"crypto/cipher"
	"testing"

	xtsreference "github.com/emmansun/gmsm/internal/cipher/xts"
	"github.com/emmansun/gmsm/internal/cryptotest/diff"
)

// diffTweakKey is the XTS tweak key used by the differential suites; it is
// derived from the KAT key so that every key is pinned and reproducible from
// the case descriptor alone.
var diffTweakKey = func() []byte {
	k := make([]byte, len(katKey))
	for i, v := range katKey {
		k[i] = v ^ 0xFF
	}
	return k
}()

// TestDiffStandardVector anchors the pure-Go reference (and the public
// dispatch path) to the GB/T 32906-2016 KAT before it is used as the
// differential oracle.
func TestDiffStandardVector(t *testing.T) {
	got := make([]byte, BlockSize)
	ref, _ := newCipherGeneric(katKey)
	ref.Encrypt(got, katPlaintext)
	if !bytes.Equal(got, katExpectedCipher) {
		t.Fatalf("generic reference does not reproduce the KAT: got %x", got)
	}
	pub, _ := NewCipher(katKey)
	pub.Encrypt(got, katPlaintext)
	if !bytes.Equal(got, katExpectedCipher) {
		t.Fatalf("public dispatch does not reproduce the KAT: got %x", got)
	}
}

// diffBlockRunOf wraps a cipher.Block constructor into a diff.Run that
// encrypts or decrypts the case buffer according to Tag bit 0 (0=encrypt,
// 1=decrypt) and returns the output as a copy (the guarded Dst is verified
// by the framework).
func diffBlockRunOf(newBlock func() cipher.Block) diff.Run[[]byte] {
	return func(t testing.TB, c diff.Case, b *diff.Buffers) []byte {
		blk := newBlock()
		if c.Tag&1 == 0 {
			blk.Encrypt(b.Dst, b.Src)
		} else {
			blk.Decrypt(b.Dst, b.Src)
		}
		return append([]byte(nil), b.Dst...)
	}
}

func diffBlockRef(t testing.TB, c diff.Case, b *diff.Buffers) []byte {
	return diffBlockRunOf(func() cipher.Block {
		blk, _ := newCipherGeneric(katKey)
		return blk
	})(t, c, b)
}

func diffBlockDomain() diff.Domain {
	return diff.Domain{
		Lengths:       []int{BlockSize}, // single-block domain: exactly one block
		Tags:          []uint64{0, 1},   // bit 0: 0=encrypt, 1=decrypt
		CartesianTags: true,
		Alignments:    diff.CommonAlignments(),
		Overlaps:      []diff.OverlapCase{diff.NoOverlap(), diff.ExactOverlap()},
		Patterns:      diff.DefaultPatterns(),
		Seeds:         []uint64{0, 1},
	}
}

// TestDiffBlock checks the single-block kernels and the public dispatch path
// against the pure-Go kernel over the structured input domain.
func TestDiffBlock(t *testing.T) {
	s := diff.ByteSuite("generic-block", diffBlockRef)
	s.Add(diff.Implementation[[]byte]{
		Name: "public",
		Run:  diffBlockRunOf(func() cipher.Block { blk, _ := NewCipher(katKey); return blk }),
	})
	for _, impl := range asmBlockImpls(true) {
		s.Add(impl)
	}
	s.Run(t, diffBlockDomain())
}

// FuzzDiffBlock fuzzes the unforced implementations (public dispatch and the
// natively selected kernels). Kernels that need global dispatch overrides are
// excluded, because fuzz bodies must not mutate global state.
func FuzzDiffBlock(f *testing.F) {
	s := diff.ByteSuite("generic-block", diffBlockRef)
	s.Add(diff.Implementation[[]byte]{
		Name: "public",
		Run:  diffBlockRunOf(func() cipher.Block { blk, _ := NewCipher(katKey); return blk }),
	})
	for _, impl := range asmBlockImpls(false) {
		s.Add(impl)
	}
	s.Fuzz(f, diffBlockDomain())
}

// TestDiffMultiBlock checks the batched EncryptBlocks/DecryptBlocks kernels
// against a loop of pure-Go single-block encryptions. The legal input lengths
// are kernel specific (declared by multiBlockImpls).
func TestDiffMultiBlock(t *testing.T) {
	for _, m := range multiBlockImpls() {
		m := m
		t.Run(m.impl.Name, func(t *testing.T) {
			ref := func(t testing.TB, c diff.Case, b *diff.Buffers) []byte {
				blk, _ := newCipherGeneric(katKey)
				for i := 0; i+BlockSize <= len(b.Src); i += BlockSize {
					if c.Tag&1 == 0 {
						blk.Encrypt(b.Dst[i:], b.Src[i:])
					} else {
						blk.Decrypt(b.Dst[i:], b.Src[i:])
					}
				}
				return append([]byte(nil), b.Dst...)
			}
			s := diff.ByteSuite("generic-block-loop", ref)
			s.Add(m.impl)
			s.Run(t, diff.Domain{
				Lengths:       m.lengths,
				Tags:          []uint64{0, 1}, // bit 0: 0=EncryptBlocks, 1=DecryptBlocks
				CartesianTags: true,
				Alignments:    diff.CommonAlignments(),
				Overlaps:      []diff.OverlapCase{diff.NoOverlap(), diff.ExactOverlap()},
				Patterns:      diff.DefaultPatterns(),
				Seeds:         []uint64{0, 1},
			})
		})
	}
}

// diffXTSRunOf wraps a BlockMode constructor into a diff.Run. The tweak is
// derived from the case seed; the encrypted tweak is computed with the
// pure-Go tweak-key cipher so that reference and implementations start from
// the same value. Tag bit 0 selects the direction (0=encrypt, 1=decrypt),
// Tag bit 1 selects isGB (GB/T 17964-2021 vs IEEE P1619).
func diffXTSRunOf(newMode func(tweak, encryptedTweak *[BlockSize]byte, isGB, enc bool) (cipher.BlockMode, error)) diff.Run[[]byte] {
	return func(t testing.TB, c diff.Case, b *diff.Buffers) []byte {
		var tweak [BlockSize]byte
		diff.NewPRNG(c.Seed ^ 0x545745414B).Fill(tweak[:])
		var encryptedTweak [BlockSize]byte
		k2, _ := newCipherGeneric(diffTweakKey)
		k2.Encrypt(encryptedTweak[:], tweak[:])
		mode, err := newMode(&tweak, &encryptedTweak, c.Tag&2 != 0, c.Tag&1 == 0)
		if err != nil {
			t.Fatalf("failed to construct XTS mode: %v", err)
		}
		mode.CryptBlocks(b.Dst, b.Src)
		return append([]byte(nil), b.Dst...)
	}
}

func diffXTSRef(t testing.TB, c diff.Case, b *diff.Buffers) []byte {
	return diffXTSRunOf(func(tweak, encryptedTweak *[BlockSize]byte, isGB, enc bool) (cipher.BlockMode, error) {
		if enc {
			return xtsreference.NewXTSEncrypter(newCipherGeneric, katKey, diffTweakKey, tweak[:], isGB)
		}
		return xtsreference.NewXTSDecrypter(newCipherGeneric, katKey, diffTweakKey, tweak[:], isGB)
	})(t, c, b)
}

func diffXTSDomain() diff.Domain {
	return diff.Domain{
		// API contract: at least one full block; the boundary set covers the
		// CTS tails, the 4/8-block batch straddles and exact multiples.
		Lengths: diff.Values(16, 17, 31, 32, 33, 47, 48, 49, 64, 65, 127, 128, 129,
			143, 144, 159, 160, 255, 256, 257, 383, 384, 511, 512, 1023, 1024, 4095, 4096),
		Tags:       []uint64{0, 1, 2, 3}, // bit0: direction, bit1: isGB
		Alignments: diff.CommonAlignments(),
		Overlaps:   []diff.OverlapCase{diff.NoOverlap(), diff.ExactOverlap()},
		Patterns:   diff.DefaultPatterns(),
		Seeds:      []uint64{0, 1},
	}
}

// TestDiffXTS checks the XTS BlockModes (public dispatch path and the direct
// asm kernels) against the pure-Go XTS implementation over the generic block.
func TestDiffXTS(t *testing.T) {
	s := diff.ByteSuite("generic-xts", diffXTSRef)
	s.Add(diff.Implementation[[]byte]{
		Name: "public",
		Run: diffXTSRunOf(func(tweak, encryptedTweak *[BlockSize]byte, isGB, enc bool) (cipher.BlockMode, error) {
			if enc {
				return xtsreference.NewXTSEncrypter(NewCipher, katKey, diffTweakKey, tweak[:], isGB)
			}
			return xtsreference.NewXTSDecrypter(NewCipher, katKey, diffTweakKey, tweak[:], isGB)
		}),
	})
	for _, impl := range asmXTSImpls() {
		s.Add(impl)
	}
	s.Run(t, diffXTSDomain())
}

// FuzzDiffXTS fuzzes the XTS modes; none of the implementations mutate
// global dispatch state, so all of them are safe for fuzz bodies.
func FuzzDiffXTS(f *testing.F) {
	s := diff.ByteSuite("generic-xts", diffXTSRef)
	s.Add(diff.Implementation[[]byte]{
		Name: "public",
		Run: diffXTSRunOf(func(tweak, encryptedTweak *[BlockSize]byte, isGB, enc bool) (cipher.BlockMode, error) {
			if enc {
				return xtsreference.NewXTSEncrypter(NewCipher, katKey, diffTweakKey, tweak[:], isGB)
			}
			return xtsreference.NewXTSDecrypter(NewCipher, katKey, diffTweakKey, tweak[:], isGB)
		}),
	})
	for _, impl := range asmXTSImpls() {
		s.Add(impl)
	}
	s.Fuzz(f, diffXTSDomain())
}

// diffGCMRunOf wraps an AEAD constructor into a diff.Run. Tag encodes
// (aadLength << 1) | direction (0=seal, 1=open). The output is allocated by
// the AEAD itself (Go append semantics), so the guarded buffers verify that
// the input is never modified; output parity is checked against the
// reference.
func diffGCMRunOf(newAEAD func() (cipher.AEAD, error)) diff.Run[[]byte] {
	return func(t testing.TB, c diff.Case, b *diff.Buffers) []byte {
		aead, err := newAEAD()
		if err != nil {
			t.Fatalf("failed to construct AEAD: %v", err)
		}
		// gcmStandardNonceSize; the constants are only defined on the
		// accelerated build configurations, so this file uses literals.
		nonce := make([]byte, 12)
		diff.NewPRNG(c.Seed ^ 0x4E4F4E4345).Fill(nonce)
		aad := make([]byte, int(c.Tag>>1))
		diff.NewPRNG(c.Seed ^ 0x41414444415441).Fill(aad)
		ct := aead.Seal(nil, nonce, b.Src, aad)
		if c.Tag&1 == 0 {
			return ct
		}
		refBlock, err := newCipherGeneric(katKey)
		if err != nil {
			t.Fatal(err)
		}
		refAEAD, err := cipher.NewGCM(refBlock)
		if err != nil {
			t.Fatal(err)
		}
		refCT := refAEAD.Seal(nil, nonce, b.Src, aad)
		out, err := aead.Open(nil, nonce, refCT, aad)
		if err != nil {
			t.Fatalf("open failed: %v", err)
		}
		return append(ct, out...)
	}
}

func TestDiffGCMOpenComparesCiphertext(t *testing.T) {
	c := diff.Case{SrcLen: 33, DstLen: 49, Overlap: diff.NoOverlap(), Pattern: diff.DeterministicRandom(), Seed: 7, Tag: 32}
	b := diff.Materialize(c)
	sealed := diffGCMRef(t, c, b)
	c.Tag |= 1
	opened := diffGCMRef(t, c, b)
	if !bytes.Equal(opened, append(sealed, b.Src...)) {
		t.Fatal("Open differential output must include ciphertext and plaintext")
	}
}

func diffGCMRef(t testing.TB, c diff.Case, b *diff.Buffers) []byte {
	return diffGCMRunOf(func() (cipher.AEAD, error) {
		blk, err := newCipherGeneric(katKey)
		if err != nil {
			return nil, err
		}
		return cipher.NewGCM(blk)
	})(t, c, b)
}

func diffGCMDomain() diff.Domain {
	lengths := diff.Values(0, 1, 15, 16, 17, 31, 32, 33, 63, 64, 65, 127, 128, 129, 255, 256, 511, 512, 1024, 4096)
	dstLengths := make([]int, len(lengths))
	for i, n := range lengths {
		dstLengths[i] = n + 16 // + gcmTagSize
	}
	var tags []uint64
	for _, aadLen := range diff.Values(0, 1, 16, 33, 63, 64) {
		tags = append(tags, uint64(aadLen*2), uint64(aadLen*2+1))
	}
	return diff.Domain{
		Lengths:    lengths,
		DstLengths: dstLengths,
		Tags:       tags, // (aad length << 1) | direction (0=seal, 1=open)
		Alignments: diff.SingleAlignment(),
		Overlaps:   []diff.OverlapCase{diff.NoOverlap()},
		Patterns:   diff.DefaultPatterns(),
		Seeds:      []uint64{0, 1},
	}
}

// TestDiffGCM checks every GCM variant (asm GHASH + asm block, pure-Go GHASH
// + asm block, SM4-NI variants and the public dispatch path) against the
// standard library GCM over the pure-Go block.
func TestDiffGCM(t *testing.T) {
	s := diff.ByteSuite("stdlib-gcm", diffGCMRef)
	s.Add(diff.Implementation[[]byte]{
		Name: "public",
		Run: diffGCMRunOf(func() (cipher.AEAD, error) {
			blk, err := NewCipher(katKey)
			if err != nil {
				return nil, err
			}
			return cipher.NewGCM(blk)
		}),
	})
	for _, impl := range asmGCMImpls() {
		s.Add(impl)
	}
	s.Run(t, diffGCMDomain())
}

// TestDispatchSelectedImplementation verifies that the public dispatch path
// selects the concrete implementation implied by the current dispatch state.
// CI reruns it in separate go test processes with DISABLE_SM4NI=1,
// DISABLE_GFNI=1, FORCE_SM4BLOCK_AESNI=1 etc. to cover the other states.
func TestDispatchSelectedImplementation(t *testing.T) {
	checkDispatch(t)
}
