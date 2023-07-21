//go:build amd64 && !purego
// +build amd64,!purego

package bn256

// gfP2 multiplication.
//
//go:noescape
func gfp2Mul(c, a, b *gfP2)

// gfP2 multiplication. c = a*b*u
//
//go:noescape
func gfp2MulU(c, a, b *gfP2)

// gfP2 square.
//
//go:noescape
func gfp2Square(c, a *gfP2)

// gfP2 square and mult u.
//
//go:noescape
func gfp2SquareU(c, a *gfP2)

// Point doubling. Sets res = in + in. in can be the point at infinity.
//
//go:noescape
func curvePointDouble(c, a *curvePoint)

// Point addition. Sets res = in1 + in2. Returns one if the two input points
// were equal and zero otherwise. If in1 or in2 are the point at infinity, res
// and the return value are undefined.
//
//go:noescape
func curvePointAdd(c, a, b *curvePoint) int
