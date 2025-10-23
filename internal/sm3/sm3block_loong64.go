// Copyright 2025 Sun Yimin. All rights reserved.
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file.

//go:build !purego

package sm3

import "github.com/emmansun/gmsm/internal/deps/cpu"

var (
	supportLSX  = cpu.Loong64.HasLSX
	supportLASX = cpu.Loong64.HasLASX
)

//go:noescape
func blockAsm(dig *digest, p []byte)

//go:noescape
func blockLsx(dig *digest, p []byte)

func block(dig *digest, p []byte) {
	switch {
	//case supportLASX:
	//	blockLasx(dig, p)
	case supportLSX:
		blockLsx(dig, p)
	default:
		blockAsm(dig, p)
	}
}
