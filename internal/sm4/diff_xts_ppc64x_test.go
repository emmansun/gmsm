// Copyright 2026 Sun Yimin. All rights reserved.
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file.

//go:build (ppc64 || ppc64le) && !purego

package sm4

import (
	"github.com/emmansun/gmsm/internal/cryptotest/diff"
)

// asmXTSImpls returns the direct XTS kernels for ppc64x; there is no
// accelerated XTS mode on this architecture.
func asmXTSImpls() []diff.Implementation[[]byte] {
	return nil
}
