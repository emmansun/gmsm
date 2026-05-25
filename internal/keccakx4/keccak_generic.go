// Copyright 2025 Sun Yimin. All rights reserved.
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file.

//go:build purego || !(amd64 || loong64)

package keccakx4

// Permute4 applies 24 rounds of Keccak-f[1600] to all 4 interleaved states.
func Permute4(state *State4) {
	permute4Generic(state)
}
