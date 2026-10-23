// Copyright 2026 Sun Yimin. All rights reserved.
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file.

//go:build loong64 && !purego

package sm4

import (
	"os"
	"strings"
	"testing"

	"github.com/emmansun/gmsm/internal/cryptotest/diff"
	"github.com/emmansun/gmsm/internal/deps/cpu"
)

// asmBlockImpls returns the direct single-block kernels for loong64; the
// LASX acceleration only provides a batched EncryptBlocks, single-block
// encryption stays on the pure-Go kernel.
func asmBlockImpls(forced bool) []diff.Implementation[[]byte] {
	return nil
}

// diffMultiImpl pairs a batched-blocks implementation with its legal input
// lengths; the LASX kernel processes any multiple of the block size.
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
	if !supportLASX {
		return nil
	}
	c := &sm4CipherGCM{sm4CipherAsm{sm4Cipher{}, 8, 8 * BlockSize}}
	expandKeyGo(katKey, &c.enc, &c.dec)
	return []diffMultiImpl{{
		impl: diff.Implementation[[]byte]{
			Name: "lasx-blocks",
			Run:  diffBlocksRunOf(&c.sm4CipherAsm),
		},
		lengths: diff.Values(8*BlockSize, 8*BlockSize+BlockSize, 16*BlockSize),
	}}
}

// asmXTSImpls returns the direct XTS kernels for loong64; there is no
// accelerated XTS mode on this architecture.
func asmXTSImpls() []diff.Implementation[[]byte] {
	return nil
}

// asmGCMImpls returns the GCM variants for loong64; there is no accelerated
// GCM on this architecture (the public path uses the standard library GCM
// over the LASX block, exercised through the public implementation).
func asmGCMImpls() []diff.Implementation[[]byte] {
	return nil
}

// checkDispatch asserts that the public dispatch path selects the concrete
// implementation implied by the current dispatch state.
func checkDispatch(t *testing.T) {
	block, err := NewCipher(katKey)
	if err != nil {
		t.Fatal(err)
	}
	if supportLASX {
		if _, ok := block.(*sm4CipherAsm); !ok {
			t.Errorf("supportLASX: dispatch selected %T, want *sm4CipherAsm", block)
		}
	} else if _, ok := block.(*sm4Cipher); !ok {
		t.Errorf("no LASX support: dispatch selected %T, want *sm4Cipher", block)
	}
}

// TestDiffRequiredKernels enforces kernel availability on CI runners that
// guarantee the CPU features. DIFF_REQUIRE holds a comma-separated list of
// kernel classes; the list may be shared across packages, and each package
// validates only the classes it owns (unknown names are ignored).
func TestDiffRequiredKernels(t *testing.T) {
	req := os.Getenv("DIFF_REQUIRE")
	if req == "" {
		t.Skip("DIFF_REQUIRE not set")
	}
	for _, name := range strings.Split(req, ",") {
		switch name {
		case "lasx":
			if !cpu.Loong64.HasLASX {
				t.Errorf("kernel %q required but LASX is unavailable", name)
			}
		}
	}
}
