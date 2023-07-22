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
func curvePointDoubleComplete(c, a *curvePoint)
/*
// Point addition. Sets res = in1 + in2. in1 can be same as in2, also can be at infinity.
//
//go:noescape
func curvePointAddComplete(c, a, b *curvePoint)
*/
