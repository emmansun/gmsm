// Copyright 2026 Sun Yimin. All rights reserved.
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file.

//go:build (amd64 || arm64 || ppc64 || ppc64le || (riscv64 && go1.27)) && !purego

package sm4

import (
	"crypto/cipher"
	"os"
	"runtime"
	"strings"
	"testing"

	"github.com/emmansun/gmsm/internal/cpuid"
	"github.com/emmansun/gmsm/internal/cryptotest/diff"
	"github.com/emmansun/gmsm/internal/deps/cpu"
)

// newDiffAESKey constructs the AES-NI based sm4CipherAsm used by the AES/GFNI
// single-block kernels and the batched EncryptBlocks path.
func newDiffAESKey() *sm4CipherAsm {
	c := &sm4CipherGCM{sm4CipherAsm{sm4Cipher{}, 4, 4 * BlockSize}}
	expandKeyAsm(&katKey[0], &ck[0], &c.enc[0], &c.dec[0], INST_AES)
	return &c.sm4CipherAsm
}

// newDiffNIKey constructs the SM4-NI based cipher used by the native SM4
// instruction kernels. The caller must have checked cpuid.HasSM4.
func newDiffNIKey() *sm4CipherNI {
	c := &sm4CipherNIGCM{sm4CipherNI{sm4Cipher{}}}
	expandKeyAsm(&katKey[0], &ck[0], &c.enc[0], &c.dec[0], INST_SM4)
	return &c.sm4CipherNI
}

// asmBlockImpls returns the direct single-block kernels for this architecture.
// forced=false skips kernels that need global dispatch overrides, so that the
// result is safe for fuzz bodies.
func asmBlockImpls(forced bool) []diff.Implementation[[]byte] {
	var out []diff.Implementation[[]byte]
	if cpuid.HasSM4 {
		name := "sm4ni-block"
		if runtime.GOARCH == "riscv64" {
			name = "zvksed-block"
		}
		out = append(out, diff.Implementation[[]byte]{
			Name: name,
			Run:  diffBlockRunOf(func() cipher.Block { return newDiffNIKey() }),
		})
	}
	if forced && cpuid.HasAES && runtime.GOARCH != "riscv64" {
		out = append(out, diff.Implementation[[]byte]{
			Name: "aesni-single-block",
			Run: func(t testing.TB, c diff.Case, b *diff.Buffers) []byte {
				diff.WithValue(t, &useAESNI4SingleBlock, true)
				return diffBlockRunOf(func() cipher.Block { return newDiffAESKey() })(t, c, b)
			},
		})
	}
	if forced && runtime.GOARCH == "amd64" && cpuid.HasGFNI && cpu.X86.HasAVX2 {
		out = append(out, diff.Implementation[[]byte]{
			Name: "gfni-single-block",
			Run: func(t testing.TB, c diff.Case, b *diff.Buffers) []byte {
				diff.WithValue(t, &useAESNI4SingleBlock, true)
				diff.WithValue(t, &useGFNI, true)
				return diffBlockRunOf(func() cipher.Block { return newDiffAESKey() })(t, c, b)
			},
		})
	}
	return out
}

// diffMultiImpl pairs a batched-blocks implementation with its legal input
// lengths. On amd64/arm64/ppc64x encryptBlocksAsm processes exactly one batch
// (4 blocks, or 8 when the input length is 128), while riscv64 (zvksed)
// processes any multiple of the block size.
type diffMultiImpl struct {
	impl    diff.Implementation[[]byte]
	lengths []int
}

// diffBlocksRunOf wraps an sm4CipherAsm into a diff.Run dispatching to
// EncryptBlocks/DecryptBlocks by Tag bit 0.
func diffBlocksRunOf(c *sm4CipherAsm) diff.Run[[]byte] {
	return func(t testing.TB, cse diff.Case, b *diff.Buffers) []byte {
		if cse.Tag&1 == 0 {
			c.EncryptBlocks(b.Dst, b.Src)
		} else {
			c.DecryptBlocks(b.Dst, b.Src)
		}
		return append([]byte(nil), b.Dst...)
	}
}

func multiBlockImpls() []diffMultiImpl {
	if runtime.GOARCH == "riscv64" {
		if !cpuid.HasSM4 {
			return nil
		}
		c := &sm4CipherAsm{sm4Cipher{}, 4, 4 * BlockSize}
		expandKeyAsm(&katKey[0], &ck[0], &c.enc[0], &c.dec[0], INST_AES)
		return []diffMultiImpl{{
			impl: diff.Implementation[[]byte]{
				Name: "zvksed-blocks",
				Run:  diffBlocksRunOf(c),
			},
			lengths: diff.Values(4*BlockSize, 8*BlockSize, 16*BlockSize),
		}}
	}
	if !cpuid.HasAES {
		return nil
	}
	lengths := diff.Values(4*BlockSize, 8*BlockSize)
	if runtime.GOARCH == "amd64" && useAVX2 {
		// the wrapper rejects inputs smaller than the batch size
		lengths = diff.Values(8 * BlockSize)
	}
	return []diffMultiImpl{{
		impl: diff.Implementation[[]byte]{
			Name: "aesni-blocks",
			Run:  diffBlocksRunOf(newDiffAESKey()),
		},
		lengths: lengths,
	}}
}

// checkDispatch asserts that the public dispatch path selects the concrete
// implementation implied by the current dispatch state.
func checkDispatch(t *testing.T) {
	block, err := NewCipher(katKey)
	if err != nil {
		t.Fatal(err)
	}
	switch {
	case supportSM4:
		switch block.(type) {
		case *sm4CipherNI, *sm4CipherNIGCM:
		default:
			t.Errorf("supportSM4: dispatch selected %T, want *sm4CipherNI or *sm4CipherNIGCM", block)
		}
	case !supportsAES:
		if _, ok := block.(*sm4Cipher); !ok {
			t.Errorf("no AES support: dispatch selected %T, want *sm4Cipher", block)
		}
	case supportsGFMUL:
		if _, ok := block.(*sm4CipherGCM); !ok {
			t.Errorf("AES + GFMUL: dispatch selected %T, want *sm4CipherGCM", block)
		}
	default:
		if _, ok := block.(*sm4CipherAsm); !ok {
			t.Errorf("AES without GFMUL: dispatch selected %T, want *sm4CipherAsm", block)
		}
	}
}

// TestDiffRequiredKernels enforces kernel availability on CI runners that
// guarantee the CPU features (native hardware, Intel SDE, QEMU with the
// extension enabled). DIFF_REQUIRE holds a comma-separated list of kernel
// classes; the list may be shared across packages, and each package
// validates only the classes it owns (unknown names are ignored).
func TestDiffRequiredKernels(t *testing.T) {
	req := os.Getenv("DIFF_REQUIRE")
	if req == "" {
		t.Skip("DIFF_REQUIRE not set")
	}
	for _, name := range strings.Split(req, ",") {
		switch name {
		case "sm4ni", "zvksed":
			if !cpuid.HasSM4 {
				t.Errorf("kernel %q required but cpuid.HasSM4 is false", name)
			}
		case "aes":
			if !cpuid.HasAES {
				t.Errorf("kernel %q required but cpuid.HasAES is false", name)
			}
		case "gfni":
			if !cpuid.HasGFNI || !cpu.X86.HasAVX2 {
				t.Errorf("kernel %q required but GFNI/AVX2 is unavailable", name)
			}
		}
	}
}
