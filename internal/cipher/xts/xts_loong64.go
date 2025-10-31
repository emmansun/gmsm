// Copyright 2025 Sun Yimin. All rights reserved.
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file.

//go:build !purego

package xts

import "github.com/emmansun/gmsm/internal/deps/cpu"

var supportLSX = cpu.Loong64.HasLSX

//go:noescape
func mul2Lsx(tweak *[blockSize]byte, isGB bool)

//go:noescape
func doubleTweaksLsx(tweak *[blockSize]byte, tweaks []byte, isGB bool)

func mul2(tweak *[blockSize]byte, isGB bool) {
	if supportLSX {
		mul2Lsx(tweak, isGB)
	} else {
		mul2Generic(tweak, isGB)
	}
}

func doubleTweaks(tweak *[blockSize]byte, tweaks []byte, isGB bool) {
	if supportLSX {
		doubleTweaksLsx(tweak, tweaks, isGB)
		return
	}
	count := len(tweaks) >> 4
	for i := range count {
		copy(tweaks[blockSize*i:], tweak[:])
		mul2Generic(tweak, isGB)
	}
}
