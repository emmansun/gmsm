// Package sm2ec defines/implements SM2 elliptic curve structure.
package sm2ec

import (
	"crypto/elliptic"
	"errors"
	"math/big"

	"github.com/emmansun/gmsm/internal/sm2ec"
)

var sm2p256 = &sm2Curve{newPoint: sm2ec.NewSM2P256Point}

func initSM2P256() {
	sm2p256.params = &elliptic.CurveParams{
		Name:    "sm2p256v1",
		BitSize: 256,
		P:       bigFromHex("FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFF"),
		N:       bigFromHex("FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF7203DF6B21C6052B53BBF40939D54123"),
		B:       bigFromHex("28E9FA9E9D9F5E344D5A9E4BCF6509A7F39789F515AB8F92DDBCBD414D940E93"),
		Gx:      bigFromHex("32C4AE2C1F1981195F9904466A39C9948FE30BBFF2660BE1715A4589334C74C7"),
		Gy:      bigFromHex("BC3736A2F4F6779C59BDCEE36B692153D0A9877CC62A474002DF32E52139F0A0"),
	}
}

type sm2Curve struct {
	newPoint func() *sm2ec.SM2P256Point
	params   *elliptic.CurveParams
}

func (curve *sm2Curve) Params() *elliptic.CurveParams {
	return curve.params
}

func (curve *sm2Curve) IsOnCurve(x, y *big.Int) bool {
	// IsOnCurve is documented to reject (0, 0), the conventional point at
	// infinity, which however is accepted by pointFromAffine.
	if x.Sign() == 0 && y.Sign() == 0 {
		return false
	}
	_, err := curve.pointFromAffine(x, y)
	return err == nil
}

func (curve *sm2Curve) pointFromAffine(x, y *big.Int) (p *sm2ec.SM2P256Point, err error) {
	// (0, 0) is by convention the point at infinity, which can't be represented
	// in affine coordinates. See Issue 37294.
	if x.Sign() == 0 && y.Sign() == 0 {
		return curve.newPoint(), nil
	}
	// Reject values that would not get correctly encoded.
	if x.Sign() < 0 || y.Sign() < 0 {
		return p, errors.New("negative coordinate")
	}
	if x.BitLen() > curve.params.BitSize || y.BitLen() > curve.params.BitSize {
		return p, errors.New("overflowing coordinate")
	}
	// Encode the coordinates and let SetBytes reject invalid points.
	byteLen := (curve.params.BitSize + 7) / 8
	buf := make([]byte, 1+2*byteLen)
	buf[0] = 4 // uncompressed point
	x.FillBytes(buf[1 : 1+byteLen])
	y.FillBytes(buf[1+byteLen : 1+2*byteLen])
	return curve.newPoint().SetBytes(buf)
}

func (curve *sm2Curve) pointToAffine(p *sm2ec.SM2P256Point) (x, y *big.Int) {
	out := p.Bytes()
	if len(out) == 1 && out[0] == 0 {
		// This is the encoding of the point at infinity, which the affine
		// coordinates API represents as (0, 0) by convention.
		return new(big.Int), new(big.Int)
	}
	byteLen := (curve.params.BitSize + 7) / 8
	x = new(big.Int).SetBytes(out[1 : 1+byteLen])
	y = new(big.Int).SetBytes(out[1+byteLen:])
	return x, y
}

func (curve *sm2Curve) Add(x1, y1, x2, y2 *big.Int) (*big.Int, *big.Int) {
	p1, err := curve.pointFromAffine(x1, y1)
	if err != nil {
		panic("sm2/elliptic: Add was called on an invalid point")
	}
	p2, err := curve.pointFromAffine(x2, y2)
	if err != nil {
		panic("sm2/elliptic: Add was called on an invalid point")
	}
	return curve.pointToAffine(p1.Add(p1, p2))
}

func (curve *sm2Curve) Double(x1, y1 *big.Int) (*big.Int, *big.Int) {
	p, err := curve.pointFromAffine(x1, y1)
	if err != nil {
		panic("sm2/elliptic: Double was called on an invalid point")
	}
	return curve.pointToAffine(p.Double(p))
}

// normalizeScalar brings the scalar within the byte size of the order of the
// curve, as expected by the nistec scalar multiplication functions.
func (curve *sm2Curve) normalizeScalar(scalar []byte) []byte {
	byteSize := (curve.params.N.BitLen() + 7) / 8
	if len(scalar) == byteSize {
		return scalar
	}
	s := new(big.Int).SetBytes(scalar)
	if len(scalar) > byteSize {
		s.Mod(s, curve.params.N)
	}
	out := make([]byte, byteSize)
	return s.FillBytes(out)
}

func (curve *sm2Curve) ScalarMult(Bx, By *big.Int, scalar []byte) (*big.Int, *big.Int) {
	p, err := curve.pointFromAffine(Bx, By)
	if err != nil {
		panic("sm2/elliptic: ScalarMult was called on an invalid point")
	}
	scalar = curve.normalizeScalar(scalar)
	p, err = p.ScalarMult(p, scalar)
	if err != nil {
		panic("sm2/elliptic: sm2 rejected normalized scalar")
	}
	return curve.pointToAffine(p)
}

func (curve *sm2Curve) ScalarBaseMult(scalar []byte) (*big.Int, *big.Int) {
	scalar = curve.normalizeScalar(scalar)
	p, err := curve.newPoint().ScalarBaseMult(scalar)
	if err != nil {
		panic("sm2/elliptic: sm2 rejected normalized scalar")
	}
	return curve.pointToAffine(p)
}

// CombinedMult returns [s1]G + [s2]P where G is the generator. It's used
// through an interface upgrade in crypto/ecdsa.
func (curve *sm2Curve) CombinedMult(Px, Py *big.Int, s1, s2 []byte) (x, y *big.Int) {
	s1 = curve.normalizeScalar(s1)
	q, err := curve.newPoint().ScalarBaseMult(s1)
	if err != nil {
		panic("sm2/elliptic: sm2 rejected normalized scalar")
	}
	p, err := curve.pointFromAffine(Px, Py)
	if err != nil {
		panic("sm2/elliptic: CombinedMult was called on an invalid point")
	}
	s2 = curve.normalizeScalar(s2)
	p, err = p.ScalarMult(p, s2)
	if err != nil {
		panic("sm2/elliptic: sm2 rejected normalized scalar")
	}
	return curve.pointToAffine(p.Add(p, q))
}

func (curve *sm2Curve) Unmarshal(data []byte) (x, y *big.Int) {
	if len(data) == 0 || data[0] != 4 {
		return nil, nil
	}
	// Use SetBytes to check that data encodes a valid point.
	_, err := curve.newPoint().SetBytes(data)
	if err != nil {
		return nil, nil
	}
	// We don't use pointToAffine because it involves an expensive field
	// inversion to convert from Jacobian to affine coordinates, which we
	// already have.
	byteLen := (curve.params.BitSize + 7) / 8
	x = new(big.Int).SetBytes(data[1 : 1+byteLen])
	y = new(big.Int).SetBytes(data[1+byteLen:])
	return x, y
}

func (curve *sm2Curve) UnmarshalCompressed(data []byte) (x, y *big.Int) {
	if len(data) == 0 || (data[0] != 2 && data[0] != 3) {
		return nil, nil
	}
	p, err := curve.newPoint().SetBytes(data)
	if err != nil {
		return nil, nil
	}
	return curve.pointToAffine(p)
}

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
	inverse, err := sm2ec.P256OrdInverse(scalar)
	if err != nil {
		panic("sm2/elliptic: sm2 rejected normalized scalar")
	}
	return new(big.Int).SetBytes(inverse)
}

func bigFromHex(s string) *big.Int {
	b, ok := new(big.Int).SetString(s, 16)
	if !ok {
		panic("sm2/elliptic: internal error: invalid encoding")
	}
	return b
}
