// Copyright 2026 Sun Yimin. All rights reserved.
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file.

//go:build !purego

package bn256

import "github.com/emmansun/gmsm/internal/deps/cpu"

var supportRVV = cpu.RISCV64.HasV

// If cond is 0, sets res = b, otherwise sets res = a.
//
//go:noescape
func gfP12MovCondRVV(res, a, b *gfP12, cond int)

// If cond is 0, sets res = b, otherwise sets res = a.
//
//go:noescape
func curvePointMovCondRVV(res, a, b *curvePoint, cond int)

// If cond is 0, sets res = b, otherwise sets res = a.
//
//go:noescape
func twistPointMovCondRVV(res, a, b *twistPoint, cond int)

//go:noescape
func gfpCopyRVV(res, in *gfP)

//go:noescape
func gfp2CopyRVV(res, in *gfP2)

//go:noescape
func gfp4CopyRVV(res, in *gfP4)

//go:noescape
func gfp6CopyRVV(res, in *gfP6)

//go:noescape
func gfp12CopyRVV(res, in *gfP12)

// If cond is 0, sets res = b, otherwise sets res = a.
func gfP12MovCond(res, a, b *gfP12, cond int) {
	if supportRVV {
		gfP12MovCondRVV(res, a, b, cond)
		return
	}
	res.Select(a, b, cond)
}

// If cond is 0, sets res = b, otherwise sets res = a.
func curvePointMovCond(res, a, b *curvePoint, cond int) {
	if supportRVV {
		curvePointMovCondRVV(res, a, b, cond)
		return
	}
	res.x.Select(&a.x, &b.x, cond)
	res.y.Select(&a.y, &b.y, cond)
	res.z.Select(&a.z, &b.z, cond)
	res.t.Select(&a.t, &b.t, cond)
}

// If cond is 0, sets res = b, otherwise sets res = a.
func twistPointMovCond(res, a, b *twistPoint, cond int) {
	if supportRVV {
		twistPointMovCondRVV(res, a, b, cond)
		return
	}
	res.x.Select(&a.x, &b.x, cond)
	res.y.Select(&a.y, &b.y, cond)
	res.z.Select(&a.z, &b.z, cond)
	res.t.Select(&a.t, &b.t, cond)
}

func gfpCopy(res, in *gfP) {
	if supportRVV {
		gfpCopyRVV(res, in)
		return
	}
	res[0] = in[0]
	res[1] = in[1]
	res[2] = in[2]
	res[3] = in[3]
}

func gfp2Copy(res, in *gfP2) {
	if supportRVV {
		gfp2CopyRVV(res, in)
		return
	}
	gfpCopy(&res.x, &in.x)
	gfpCopy(&res.y, &in.y)
}

func gfp4Copy(res, in *gfP4) {
	if supportRVV {
		gfp4CopyRVV(res, in)
		return
	}
	gfpCopy(&res.x.x, &in.x.x)
	gfpCopy(&res.x.y, &in.x.y)
	gfpCopy(&res.y.x, &in.y.x)
	gfpCopy(&res.y.y, &in.y.y)
}

func gfp6Copy(res, in *gfP6) {
	if supportRVV {
		gfp6CopyRVV(res, in)
		return
	}
	gfpCopy(&res.x.x, &in.x.x)
	gfpCopy(&res.x.y, &in.x.y)
	gfpCopy(&res.y.x, &in.y.x)
	gfpCopy(&res.y.y, &in.y.y)
	gfpCopy(&res.z.x, &in.z.x)
	gfpCopy(&res.z.y, &in.z.y)
}

func gfp12Copy(res, in *gfP12) {
	if supportRVV {
		gfp12CopyRVV(res, in)
		return
	}
	gfpCopy(&res.x.x.x, &in.x.x.x)
	gfpCopy(&res.x.x.y, &in.x.x.y)
	gfpCopy(&res.x.y.x, &in.x.y.x)
	gfpCopy(&res.x.y.y, &in.x.y.y)

	gfpCopy(&res.y.x.x, &in.y.x.x)
	gfpCopy(&res.y.x.y, &in.y.x.y)
	gfpCopy(&res.y.y.x, &in.y.y.x)
	gfpCopy(&res.y.y.y, &in.y.y.y)

	gfpCopy(&res.z.x.x, &in.z.x.x)
	gfpCopy(&res.z.x.y, &in.z.x.y)
	gfpCopy(&res.z.y.x, &in.z.y.x)
	gfpCopy(&res.z.y.y, &in.z.y.y)
}
