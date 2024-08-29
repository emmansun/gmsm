//go:build purego || !(amd64 || arm64 || s390x || ppc64le)

package sm2ec

import (
	"errors"

	"github.com/emmansun/gmsm/internal/sm2ec/fiat"
)

// P256OrdInverse, sets out to in⁻¹ mod org(G). If in is zero, out will be zero.
// n-2 =
// 1111111111111111111111111111111011111111111111111111111111111111
// 1111111111111111111111111111111111111111111111111111111111111111
// 0111001000000011110111110110101100100001110001100000010100101011
// 0101001110111011111101000000100100111001110101010100000100100001
//
func P256OrdInverse(k []byte) ([]byte, error) {
	if len(k) != 32 {
		return nil, errors.New("invalid scalar length")
	}
	x := new(fiat.SM2P256OrderElement)
	_, err := x.SetBytes(k)
	if err != nil {
		return nil, err
	}
	xinv := new(fiat.SM2P256OrderElement).Invert(x)
	return xinv.Bytes(), nil
}

// P256OrdMul multiplication modulo org(G).
func P256OrdMul(in1, in2 []byte) ([]byte, error) {
	if len(in1) != 32 || len(in2) != 32 {
		return nil, errors.New("invalid scalar length")
	}
	ax := new(fiat.SM2P256OrderElement)
	ay := new(fiat.SM2P256OrderElement)
	res := new(fiat.SM2P256OrderElement)

	_, err := ax.SetBytes(in1)
	if err != nil {
		return nil, err
	}

	_, err = ay.SetBytes(in2)
	if err != nil {
		return nil, err
	}

	res = res.Mul(ax, ay)
	return res.Bytes(), nil
}
