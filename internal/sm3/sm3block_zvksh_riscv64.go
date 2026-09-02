// Copyright 2026 Sun Yimin. All rights reserved.
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file.

//go:build !purego && go1.26

package sm3

import (
	"os"

	"github.com/emmansun/gmsm/internal/deps/cpu"
)

// useZVKSH reports whether the Zvksh (vector SM3) extension is available.
var useZVKSH = cpu.RISCV64.HasZvksh && (cpu.RISCV64.HasZvbb || cpu.RISCV64.HasZvkb) && os.Getenv("DISABLE_SM3NI") != "1"

//go:noescape
func blockRISCV64(dig *digest, p []byte)

//go:noescape
func blockZVKSH(dig *digest, p []byte)

func block(dig *digest, p []byte) {
	if useZVKSH {
		blockZVKSH(dig, p)
		return
	}
	blockRISCV64(dig, p)
}
