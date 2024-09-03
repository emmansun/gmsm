// Copyright 2024 Sun Yimin. All rights reserved.
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file.

//go:build !purego

package sm3

//go:noescape
func transposeMatrix(dig **[8]uint32)

//go:noescape
func copyResultsBy4(dig *uint32, p *byte)
