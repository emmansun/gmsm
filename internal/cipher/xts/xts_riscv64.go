// Copyright 2026 Sun Yimin. All rights reserved.
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file.

//go:build !purego

package xts

import "github.com/emmansun/gmsm/internal/deps/cpu"

//go:noescape
func mul2Asm(tweak *[blockSize]byte, isGB bool)
	
//go:noescape
func doubleTweaksAsm(tweak *[blockSize]byte, tweaks []byte, isGB bool)

func mul2(tweak *[blockSize]byte, isGB bool) {
	if cpu.RISCV64.HasV {
		mul2Asm(tweak, isGB)
		return
	}
	mul2Generic(tweak, isGB)
}

func doubleTweaks(tweak *[blockSize]byte, tweaks []byte, isGB bool) {
	if cpu.RISCV64.HasV {
		doubleTweaksAsm(tweak, tweaks, isGB)
		return
	}
	count := len(tweaks) >> 4
	for i := range count {
		copy(tweaks[blockSize*i:], tweak[:])
		mul2(tweak, isGB)
	}
}
