//go:build tablegen
// +build tablegen

package sm2

// This block exports p256-related internals for the p256 table generator in internal/gen.
var (
	P256PointDoubleAsm = p256PointDoubleAsm
	P256PointAddAsm    = p256PointAddAsm
	P256Inverse        = p256Inverse
	P256Sqr            = p256Sqr
	P256Mul            = p256Mul
)
