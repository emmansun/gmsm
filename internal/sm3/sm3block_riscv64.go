// Copyright 2025 Sun Yimin. All rights reserved.
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file.

//go:build !purego

package sm3

//go:noescape
func block(dig *digest, p []byte)

//go:noescape
func blocktest(p []byte)
