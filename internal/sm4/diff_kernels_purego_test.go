// Copyright 2026 Sun Yimin. All rights reserved.
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file.

//go:build purego || !(amd64 || arm64 || ppc64 || ppc64le || loong64 || (riscv64 && go1.27))

package sm4

import (
	"testing"

	"github.com/emmansun/gmsm/internal/cryptotest/diff"
)

// asmBlockImpls returns the direct single-block kernels; the pure-Go build
// has no accelerated kernels, the public dispatch path is the generic one.
func asmBlockImpls(forced bool) []diff.Implementation[[]byte] {
	return nil
}

// diffMultiImpl pairs a batched-blocks implementation with its legal input
// lengths; unused on the pure-Go build.
type diffMultiImpl struct {
	impl    diff.Implementation[[]byte]
	lengths []int
}

func multiBlockImpls() []diffMultiImpl {
	return nil
}

// asmXTSImpls returns the direct XTS kernels; unused on the pure-Go build.
func asmXTSImpls() []diff.Implementation[[]byte] {
	return nil
}

// asmGCMImpls returns the GCM variants; unused on the pure-Go build.
func asmGCMImpls() []diff.Implementation[[]byte] {
	return nil
}

// checkDispatch asserts that the public dispatch path selects the generic
// implementation on the pure-Go build.
func checkDispatch(t *testing.T) {
	block, err := NewCipher(katKey)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := block.(*sm4Cipher); !ok {
		t.Errorf("purego build: dispatch selected %T, want *sm4Cipher", block)
	}
}
