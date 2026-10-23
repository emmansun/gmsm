// Copyright 2026 Sun Yimin. All rights reserved.
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file.

package xts

import (
	"crypto/aes"
	"crypto/cipher"
	"testing"

	"github.com/emmansun/gmsm/internal/cryptotest/diff"
)

// diffXTSKey and diffXTSTweakKey are pinned AES-128 key material so that
// every case is reproducible from its descriptor alone.
var (
	diffXTSKey = []byte{
		0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
		0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
	}
	diffXTSTweakKey = []byte{
		0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7,
		0xf8, 0xf9, 0xfa, 0xfb, 0xfc, 0xfd, 0xfe, 0xff,
	}
)

// diffRefMul2 is the specification-based GF(2^128) tweak doubling written
// directly from IEEE P1619 (isGB=false, left shift with the x^128+x^7+x^2+x+1
// feedback) and GB/T 17964-2021 (isGB=true, right shift with the 0xe1
// feedback). It is the differential oracle for the mul2/doubleTweaks kernels.
func diffRefMul2(tweak *[blockSize]byte, isGB bool) {
	var carry byte
	if !isGB {
		for i := range tweak {
			carryOut := tweak[i] >> 7
			tweak[i] = tweak[i]<<1 | carry
			carry = carryOut
		}
		if carry != 0 {
			tweak[0] ^= GF128_FDBK
		}
	} else {
		for i := range tweak {
			carryOut := (tweak[i] << 7) & 0x80
			tweak[i] = tweak[i]>>1 | carry
			carry = carryOut
		}
		if carry != 0 {
			tweak[0] ^= 0xe1
		}
	}
}

// TestDiffMul2 checks the mul2 kernel against the specification-based
// doubling over random tweak values; tag bit 0 selects isGB.
func TestDiffMul2(t *testing.T) {
	run := func(t testing.TB, c diff.Case, b *diff.Buffers) []byte {
		var tweak [blockSize]byte
		copy(tweak[:], b.Src)
		diffRefMul2(&tweak, c.Tag&1 != 0)
		return append([]byte(nil), tweak[:]...)
	}
	s := diff.ByteSuite("spec-mul2", run)
	s.Add(diff.Implementation[[]byte]{
		Name: "mul2",
		Run: func(t testing.TB, c diff.Case, b *diff.Buffers) []byte {
			var tweak [blockSize]byte
			copy(tweak[:], b.Src)
			mul2(&tweak, c.Tag&1 != 0)
			return append([]byte(nil), tweak[:]...)
		},
	})
	s.Run(t, diff.Domain{
		Lengths:       []int{blockSize},
		Tags:          []uint64{0, 1}, // bit 0: isGB
		CartesianTags: true,
		Alignments:    diff.CommonAlignments(),
		Overlaps:      []diff.OverlapCase{diff.NoOverlap()},
		Patterns:      diff.DefaultPatterns(),
		Seeds:         []uint64{0, 1, 2, 3},
	})
}

// TestDiffDoubleTweaks checks the doubleTweaks kernel against a loop of the
// specification-based doubling. The output is the tweak sequence followed by
// the advanced tweak value, matching the kernel's in/out contract.
func TestDiffDoubleTweaks(t *testing.T) {
	runOf := func(fn func(tweak *[blockSize]byte, tweaks []byte, isGB bool)) diff.Run[[]byte] {
		return func(t testing.TB, c diff.Case, b *diff.Buffers) []byte {
			var tweak [blockSize]byte
			diff.NewPRNG(c.Seed ^ 0x545745414B).Fill(tweak[:])
			fn(&tweak, b.Dst, c.Tag&1 != 0)
			return append(append([]byte(nil), b.Dst...), tweak[:]...)
		}
	}
	s := diff.ByteSuite("spec-double-tweaks",
		runOf(func(tweak *[blockSize]byte, tweaks []byte, isGB bool) {
			count := len(tweaks) >> 4
			for i := range count {
				copy(tweaks[blockSize*i:], tweak[:])
				diffRefMul2(tweak, isGB)
			}
		}))
	s.Add(diff.Implementation[[]byte]{Name: "doubleTweaks", Run: runOf(doubleTweaks)})
	s.Run(t, diff.Domain{
		Lengths:    diff.Values(16, 32, 48, 64, 80, 96, 112, 128), // whole tweak batches
		Tags:       []uint64{0, 1},                                // bit 0: isGB
		Alignments: diff.SingleAlignment(),
		Overlaps:   []diff.OverlapCase{diff.NoOverlap()},
		Patterns:   diff.DefaultPatterns(),
		Seeds:      []uint64{0, 1, 2, 3},
	})
}

// diffAESConcurrent wraps stdlib AES so that the concurrent-batch branches of
// CryptBlocks are exercised (Concurrency()=4 matches the asserted batch sizes
// of the public API).
type diffAESConcurrent struct {
	cipher.Block
}

func (b *diffAESConcurrent) Concurrency() int { return 4 }

func (b *diffAESConcurrent) EncryptBlocks(dst, src []byte) {
	for i := 0; i < len(src); i += blockSize {
		b.Block.Encrypt(dst[i:], src[i:])
	}
}

func (b *diffAESConcurrent) DecryptBlocks(dst, src []byte) {
	for i := 0; i < len(src); i += blockSize {
		b.Block.Decrypt(dst[i:], src[i:])
	}
}

func newDiffAESConcurrent(key []byte) (cipher.Block, error) {
	b, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return &diffAESConcurrent{Block: b}, nil
}

// diffRefXTS is an independent specification-based XTS implementation used as
// the differential oracle for the package's CryptBlocks paths, including the
// ciphertext-stealing and concurrent-batch branches that the kernel-level
// tests cannot cover. Correctness of this oracle is anchored by the package
// tweak-vector tests (mul2) and the public API roundtrip tests.
type diffRefXTS struct {
	b     cipher.Block
	tweak [blockSize]byte
	isGB  bool
}

func newDiffRefXTS(key, tweakKey, tweak []byte, isGB, enc bool) (*diffRefXTS, error) {
	b, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	k2, err := aes.NewCipher(tweakKey)
	if err != nil {
		return nil, err
	}
	r := &diffRefXTS{b: b, isGB: isGB}
	k2.Encrypt(r.tweak[:], tweak)
	return r, nil
}

func diffRefXOR(dst, a, b []byte) {
	for i := range dst {
		dst[i] = a[i] ^ b[i]
	}
}

func (r *diffRefXTS) cryptBlock(out, in []byte, t *[blockSize]byte, enc bool) {
	diffRefXOR(out, in, t[:])
	if enc {
		r.b.Encrypt(out, out)
	} else {
		r.b.Decrypt(out, out)
	}
	diffRefXOR(out, out, t[:])
}

// crypt implements XTS with ciphertext stealing; len(dst) must equal len(src)
// and be at least one block.
func (r *diffRefXTS) crypt(dst, src []byte, enc bool) {
	n := len(src)
	d := n % blockSize
	floor := n / blockSize
	var t [blockSize]byte
	copy(t[:], r.tweak[:])
	if enc {
		for i := range floor {
			off := i * blockSize
			r.cryptBlock(dst[off:off+blockSize], src[off:off+blockSize], &t, enc)
			diffRefMul2(&t, r.isGB)
		}
		if d == 0 {
			return
		}
		last := (floor - 1) * blockSize
		var x [blockSize]byte
		copy(x[:d], src[last+blockSize:])
		copy(x[d:], dst[last+d:])
		copy(dst[last+blockSize:], dst[last:last+d])
		diffRefXOR(x[:], x[:], t[:])
		r.b.Encrypt(x[:], x[:])
		diffRefXOR(dst[last:last+blockSize], x[:], t[:])
		return
	}
	full := floor
	if d != 0 {
		full = floor - 1 // the merged block at floor-1 uses the next tweak
	}
	for i := range full {
		off := i * blockSize
		r.cryptBlock(dst[off:off+blockSize], src[off:off+blockSize], &t, enc)
		diffRefMul2(&t, r.isGB)
	}
	if d == 0 {
		return
	}
	var tt [blockSize]byte
	copy(tt[:], t[:])
	diffRefMul2(&tt, r.isGB)
	last := (floor - 1) * blockSize
	// Recover the pre-encryption merged block: tail plaintext || stolen ct.
	var x [blockSize]byte
	diffRefXOR(x[:], src[last:last+blockSize], tt[:])
	r.b.Decrypt(x[:], x[:])
	diffRefXOR(x[:], x[:], tt[:])
	// Read the tail ciphertext before the tail plaintext write below lands
	// on it, so the reference also works in place (dst == src).
	var ctTail [blockSize]byte
	copy(ctTail[:d], src[last+blockSize:])
	copy(dst[last+blockSize:], x[:d])
	// Reassemble the original last full ciphertext block and decrypt it.
	var y [blockSize]byte
	copy(y[:d], ctTail[:d])
	copy(y[d:], x[d:])
	diffRefXOR(y[:], y[:], t[:])
	r.b.Decrypt(y[:], y[:])
	diffRefXOR(dst[last:last+blockSize], y[:], t[:])
}

// diffXTSModeRunOf wraps an XTS mode constructor into a diff.Run; tag bit 0
// selects the direction (0=encrypt, 1=decrypt), tag bit 1 selects isGB.
func diffXTSModeRunOf(newMode func(key, tweakKey, tweak []byte, isGB, enc bool) (cipher.BlockMode, error)) diff.Run[[]byte] {
	return func(t testing.TB, c diff.Case, b *diff.Buffers) []byte {
		var tweak [blockSize]byte
		diff.NewPRNG(c.Seed ^ 0x545745414B).Fill(tweak[:])
		mode, err := newMode(diffXTSKey, diffXTSTweakKey, tweak[:], c.Tag&2 != 0, c.Tag&1 == 0)
		if err != nil {
			t.Fatalf("failed to construct XTS mode: %v", err)
		}
		mode.CryptBlocks(b.Dst, b.Src)
		return append([]byte(nil), b.Dst...)
	}
}

func diffXTSModeRef(t testing.TB, c diff.Case, b *diff.Buffers) []byte {
	var tweak [blockSize]byte
	diff.NewPRNG(c.Seed ^ 0x545745414B).Fill(tweak[:])
	r, err := newDiffRefXTS(diffXTSKey, diffXTSTweakKey, tweak[:], c.Tag&2 != 0, c.Tag&1 == 0)
	if err != nil {
		t.Fatalf("failed to construct reference XTS: %v", err)
	}
	r.crypt(b.Dst, b.Src, c.Tag&1 == 0)
	return append([]byte(nil), b.Dst...)
}

func diffXTSModeDomain() diff.Domain {
	return diff.Domain{
		// Sector boundaries: exact batch multiples, CTS tails and the
		// batch/CTS straddle windows of the concurrent decrypt loop.
		Lengths: diff.Values(16, 17, 31, 32, 33, 47, 48, 49, 63, 64, 65, 79, 80, 81,
			127, 128, 129, 143, 144, 145, 255, 256, 257, 511, 512, 1024),
		Tags:       []uint64{0, 1, 2, 3}, // bit0: direction, bit1: isGB
		Alignments: diff.CommonAlignments(),
		Overlaps:   []diff.OverlapCase{diff.NoOverlap(), diff.ExactOverlap()},
		Patterns:   diff.DefaultPatterns(),
		Seeds:      []uint64{0, 1},
	}
}

// TestDiffXTSMode checks the public XTS mode — with a plain block cipher and
// with a concurrent-batch block cipher — against the specification-based
// reference. There is no runtime dispatch state in this package (the kernels
// are selected by build tags), so no dispatch observability check is needed.
func TestDiffXTSMode(t *testing.T) {
	s := diff.ByteSuite("spec-xts", diffXTSModeRef)
	s.Add(diff.Implementation[[]byte]{
		Name: "aes-block",
		Run: diffXTSModeRunOf(func(key, tweakKey, tweak []byte, isGB, enc bool) (cipher.BlockMode, error) {
			if enc {
				return NewXTSEncrypter(aes.NewCipher, key, tweakKey, tweak, isGB)
			}
			return NewXTSDecrypter(aes.NewCipher, key, tweakKey, tweak, isGB)
		}),
	})
	s.Add(diff.Implementation[[]byte]{
		Name: "aes-concurrent",
		Run: diffXTSModeRunOf(func(key, tweakKey, tweak []byte, isGB, enc bool) (cipher.BlockMode, error) {
			if enc {
				return NewXTSEncrypter(newDiffAESConcurrent, key, tweakKey, tweak, isGB)
			}
			return NewXTSDecrypter(newDiffAESConcurrent, key, tweakKey, tweak, isGB)
		}),
	})
	s.Run(t, diffXTSModeDomain())
}

// FuzzDiffXTSMode fuzzes the XTS mode; every length >= one block is legal,
// so no case normalization is needed.
func FuzzDiffXTSMode(f *testing.F) {
	s := diff.ByteSuite("spec-xts", diffXTSModeRef)
	s.Add(diff.Implementation[[]byte]{
		Name: "aes-block",
		Run: diffXTSModeRunOf(func(key, tweakKey, tweak []byte, isGB, enc bool) (cipher.BlockMode, error) {
			if enc {
				return NewXTSEncrypter(aes.NewCipher, key, tweakKey, tweak, isGB)
			}
			return NewXTSDecrypter(aes.NewCipher, key, tweakKey, tweak, isGB)
		}),
	})
	s.Add(diff.Implementation[[]byte]{
		Name: "aes-concurrent",
		Run: diffXTSModeRunOf(func(key, tweakKey, tweak []byte, isGB, enc bool) (cipher.BlockMode, error) {
			if enc {
				return NewXTSEncrypter(newDiffAESConcurrent, key, tweakKey, tweak, isGB)
			}
			return NewXTSDecrypter(newDiffAESConcurrent, key, tweakKey, tweak, isGB)
		}),
	})
	s.Fuzz(f, diffXTSModeDomain())
}
