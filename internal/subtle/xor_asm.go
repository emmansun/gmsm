// Copyright 2018 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.
//
//go:build !purego && (amd64 || arm64 || ppc64 || ppc64le || riscv64 || s390x)

package subtle

import "golang.org/x/sys/cpu"

var useAVX2 = cpu.X86.HasAVX2

//go:noescape
func xorBytes(dst, a, b *byte, n int)
