// Copyright 2024 Sun Yimin. All rights reserved.
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file.

//go:build !purego

package subtle

//go:noescape
func xorBytes(dst, a, b *byte, n int)
