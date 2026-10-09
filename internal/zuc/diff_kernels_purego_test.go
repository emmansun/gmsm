// Copyright 2026 Sun Yimin. All rights reserved.
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file.

//go:build purego || !(amd64 || arm64 || ppc64 || ppc64le || (riscv64 && go1.27))

package zuc

import (
	"testing"

	"github.com/emmansun/gmsm/internal/cryptotest/diff"
)

// diffEEARefFor returns the run unchanged: the pure-Go build has a single
// keystream path, which is the reference.
func diffEEARefFor(run diff.Run[[]byte]) diff.Run[[]byte] { return run }

// diffEEAImpls returns no additional implementations; there is no dispatch
// on the pure-Go build and the KAT anchors the single path.
func diffEEAImpls(run diff.Run[[]byte]) []diff.Implementation[[]byte] { return nil }

// diffEIARefFor returns the run unchanged: the pure-Go build has a single
// MAC path, which is the reference.
func diffEIARefFor(run diff.Run[[]byte]) diff.Run[[]byte] { return run }

// diffEIAImpls returns no additional implementations.
func diffEIAImpls(run diff.Run[[]byte]) []diff.Implementation[[]byte] { return nil }

// checkDispatch is a no-op: the pure-Go build has a single code path.
func checkDispatch(t *testing.T) {}
