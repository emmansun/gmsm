// Copyright 2026 Sun Yimin. All rights reserved.
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file.

//go:build purego || !(amd64 || arm64 || ppc64 || ppc64le || s390x || loong64 || (riscv64 && go1.27))

package sm3

import (
	"testing"

	"github.com/emmansun/gmsm/internal/cryptotest/diff"
)

// sm3BlockImpls returns the block kernels; the pure-Go build has no
// accelerated kernels, block is blockGeneric.
func sm3BlockImpls() []diff.Implementation[[]byte] {
	return []diff.Implementation[[]byte]{
		{
			Name: "public-block",
			Run:  sm3BlockRunOf(block),
		},
	}
}

// checkDispatch verifies the block dispatch state; the pure-Go build has a
// single kernel, nothing to verify beyond the suite itself.
func checkDispatch(t *testing.T) {}
