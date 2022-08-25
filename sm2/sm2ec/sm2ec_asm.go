//go:build (amd64 && !generic) || (arm64 && !generic)
// +build amd64,!generic arm64,!generic

package sm2ec

import (
	"math/big"

	_sm2ec "github.com/emmansun/gmsm/internal/sm2ec"
)

// Inverse, implements invertible interface, used by Sign()
func (curve *sm2Curve) Inverse(k *big.Int) *big.Int {
	if k.Sign() < 0 {
		// This should never happen.
		k = new(big.Int).Neg(k)
	}
	if k.Cmp(curve.params.N) >= 0 {
		// This should never happen.
		k = new(big.Int).Mod(k, curve.params.N)
	}
	scalar := k.FillBytes(make([]byte, 32))
	inverse, err := _sm2ec.P256OrdInverse(scalar)
	if err != nil {
		panic("sm2/elliptic: sm2 rejected normalized scalar")
	}
	return new(big.Int).SetBytes(inverse)
}
