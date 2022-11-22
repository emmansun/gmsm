//go:build (!amd64 && !arm64) || purego
// +build !amd64,!arm64 purego

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
	_1 := new(fiat.SM2P256OrderElement)
	_, err := _1.SetBytes(k)
	if err != nil {
		return nil, err
	}

	_11 := new(fiat.SM2P256OrderElement)
	_101 := new(fiat.SM2P256OrderElement)
	_111 := new(fiat.SM2P256OrderElement)
	_1111 := new(fiat.SM2P256OrderElement)
	_10101 := new(fiat.SM2P256OrderElement)
	_101111 := new(fiat.SM2P256OrderElement)
	t := new(fiat.SM2P256OrderElement)
	m := new(fiat.SM2P256OrderElement)

	m.Square(_1)
	_11.Mul(m, _1)
	_101.Mul(m, _11)
	_111.Mul(m, _101)
	x.Square(_101)
	_1111.Mul(_101, x)

	t.Square(x)
	_10101.Mul(t, _1)
	x.Square(_10101)
	_101111.Mul(x, _101)
	x.Mul(_10101, x)
	t.Square(x)
	t.Square(t)

	m.Mul(t, m)
	t.Mul(t, _11)
	x.Square(t)
	for i := 1; i < 8; i++ {
		x.Square(x)
	}
	m.Mul(x, m)
	x.Mul(x, t)

	t.Square(x)
	for i := 1; i < 16; i++ {
		t.Square(t)
	}
	m.Mul(t, m)
	t.Mul(t, x)

	x.Square(m)
	for i := 1; i < 32; i++ {
		x.Square(x)
	}
	x.Mul(x, t)
	for i := 0; i < 32; i++ {
		x.Square(x)
	}
	x.Mul(x, t)
	for i := 0; i < 32; i++ {
		x.Square(x)
	}
	x.Mul(x, t)

	sqrs := []uint8{
		4, 3, 11, 5, 3, 5, 1,
		3, 7, 5, 9, 7, 5, 5,
		4, 5, 2, 2, 7, 3, 5,
		5, 6, 2, 6, 3, 5,
	}
	muls := []*fiat.SM2P256OrderElement{
		_111, _1, _1111, _1111, _101, _10101, _1,
		_1, _111, _11, _101, _10101, _10101, _111,
		_111, _1111, _11, _1, _1, _1, _111,
		_111, _10101, _1, _1, _1, _1}

	for i, s := range sqrs {
		for j := 0; j < int(s); j++ {
			x.Square(x)
		}
		x.Mul(x, muls[i])
	}

	return x.Bytes(), nil

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
