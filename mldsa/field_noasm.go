//go:build !amd64 || purego

package mldsa

func nttMul(out, lhs, rhs *nttElement) {
	nttMulGeneric(out, lhs, rhs)
}

func internalNTT(f *ringElement) {
	internalNTTGeneric(f)
}
