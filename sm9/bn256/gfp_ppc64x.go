// Copyright 2024 Sun Yimin. All rights reserved.
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file.

//go:build (ppc64 || ppc64le) && !purego

package bn256

// Set c = p - a, if c == p, then c = 0
// It seems this function's performance is worse than gfpSub with zero.
//
//go:noescape
func gfpNegAsm(c, a *gfP)

// Set c = a + b, if c >= p, then c = c - p
//
//go:noescape
func gfpAddAsm(c, a, b *gfP)

// Set c = a + a
//
//go:noescape
func gfpDoubleAsm(c, a *gfP)

// Set c = a + a + a
//
//go:noescape
func gfpTripleAsm(c, a *gfP)

// Set c = a - b, if c is negative, then c = c + p
//
//go:noescape
func gfpSubAsm(c, a, b *gfP)
