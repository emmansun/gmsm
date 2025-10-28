//go:build (amd64 || arm64 || ppc64 || ppc64le || loong64) && !purego

package bn256

import "github.com/emmansun/gmsm/internal/deps/cpu"

var (
	supportAVX2 = cpu.X86.HasAVX2
	supportLSX  = false
	supportLASX = false
)

// If cond is 0, sets res = b, otherwise sets res = a.
//
//go:noescape
func gfP12MovCond(res, a, b *gfP12, cond int)

// If cond is 0, sets res = b, otherwise sets res = a.
//
//go:noescape
func curvePointMovCond(res, a, b *curvePoint, cond int)

// If cond is 0, sets res = b, otherwise sets res = a.
//
//go:noescape
func twistPointMovCond(res, a, b *twistPoint, cond int)

//go:noescape
func gfpCopy(res, in *gfP)

//go:noescape
func gfp2Copy(res, in *gfP2)

//go:noescape
func gfp4Copy(res, in *gfP4)

//go:noescape
func gfp6Copy(res, in *gfP6)

//go:noescape
func gfp12Copy(res, in *gfP12)
