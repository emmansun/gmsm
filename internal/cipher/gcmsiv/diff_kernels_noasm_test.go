// Copyright 2026 Sun Yimin. All rights reserved.
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file.

//go:build purego || !(amd64 || arm64 || (riscv64 && go1.27))

package cipher

import (
	"testing"

	"github.com/emmansun/gmsm/internal/cryptotest/diff"
)

// diffPolyvalRefFor returns the run unchanged: the pure-Go build has a single
// POLYVAL path, which is the reference.
func diffPolyvalRefFor(run diff.Run[[]byte]) diff.Run[[]byte] { return run }

// diffPolyvalImpls returns no additional implementations; there is no
// dispatch on the pure-Go build and the RFC 8452 KAT anchors the single path.
func diffPolyvalImpls(run diff.Run[[]byte]) []diff.Implementation[[]byte] { return nil }

// diffGCMSIVRefFor returns the run unchanged: the pure-Go build has a single
// tag computation path, which is the reference.
func diffGCMSIVRefFor(run diff.Run[[]byte]) diff.Run[[]byte] { return run }

func diffGCMSIVReferenceSeal(seal func() []byte) []byte { return seal() }

// diffGCMSIVImpls returns no additional implementations.
func diffGCMSIVImpls(run diff.Run[[]byte]) []diff.Implementation[[]byte] { return nil }

// checkDispatch is a no-op: the pure-Go build has a single code path and no
// dispatch variables.
func checkDispatch(t *testing.T) {}
