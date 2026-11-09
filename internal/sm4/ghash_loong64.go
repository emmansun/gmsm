// Copyright 2026 Sun Yimin. All rights reserved.
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file.

//go:build loong64 && !purego

package sm4

import "github.com/emmansun/gmsm/internal/byteorder"

//go:noescape
func ghashMulLoongAsm(out *[16]byte, x0, x1 uint64, h *[16]byte)

func ghashMulLoong(out, x, h *[16]byte) {
	ghashMulLoongAsm(out, byteorder.BEUint64(x[:8]), byteorder.BEUint64(x[8:]), h)
}
