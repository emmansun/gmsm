// Copyright 2026 Sun Yimin. All rights reserved.
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file.

//go:build s390x && !purego

package sm3

import (
	"testing"

	"github.com/emmansun/gmsm/internal/cryptotest/diff"
)

// sm3BlockImpls returns the block kernels for s390x; the only kernel is the
// assembly block, which is also the dispatching block.
func sm3BlockImpls() []diff.Implementation[[]byte] {
	return []diff.Implementation[[]byte]{
		{
			Name: "public-block",
			Run:  sm3BlockRunOf(block),
		},
	}
}

// checkDispatch verifies the block dispatch state; s390x has a single
// kernel, nothing to verify beyond the suite itself.
func checkDispatch(t *testing.T) {}
