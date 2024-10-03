// Copyright 2024 Sun Yimin. All rights reserved.
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file.

//go:build (ppc64 || ppc64le) && !purego

package zuc

// Generate single keyword, 4 bytes.
//
//go:noescape
func genKeywordAsm(s *zucState32) uint32

// Generate multiple keywords, n*4 bytes.
//
//go:noescape
func genKeyStreamAsm(keyStream []uint32, pState *zucState32)

//go:noescape
func genKeyStreamRev32Asm(keyStream []byte, pState *zucState32)
