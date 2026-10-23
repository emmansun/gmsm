// Copyright 2026 Sun Yimin. All rights reserved.
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file.

//go:build (ppc64 || ppc64le) && !purego

package sm3

import (
	"testing"

	"github.com/emmansun/gmsm/internal/cryptotest/diff"
)

// sm3BlockImpls returns the block kernels for ppc64x; the only accelerated
// kernel is the dispatching block (blockASM).
func sm3BlockImpls() []diff.Implementation[[]byte] {
	return []diff.Implementation[[]byte]{
		{
			Name: "public-block",
			Run:  sm3BlockRunOf(block),
		},
	}
}

// checkDispatch verifies the block dispatch state; ppc64x has a single
// kernel, nothing to verify beyond the suite itself.
func checkDispatch(t *testing.T) {}
